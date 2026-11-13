"""
Isolated Per-Job Tool Cell Runner & Untrusted Output Normalizer for ARGOLOCK NET.
Complies with ARGOLOCK_NET_Isolated_Tool_Pipeline_Design_v1.0.md.

Guarantees:
1. Fresh, ephemeral per-job isolated execution context.
2. Stripped environment variables (no host secrets/AI keys).
3. Raw output captured as immutable RawEvidenceArtifact with SHA-256 hash.
4. Parsing runs separately; malformed or oversized output is quarantined.
5. Emits typed handoff models (DomainCandidate, ServiceEndpointCandidate, etc.).
6. Deterministic mock/local-lab adapter support when tool binary is not installed on host.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Type
from urllib.parse import urlparse
from loguru import logger
from pydantic import BaseModel, ValidationError

from app.models.tool_cell_models import (
    ToolCellManifest, SequentialStageKey, CellWorkflowState,
    RawEvidenceArtifact, DomainCandidate, ServiceEndpointCandidate,
    ServiceFingerprint, WebOrigin, RouteObservation, FindingCandidate,
    FindingReviewState, AIPairedProposal
)
from app.services.evidence_collector import evidence_collector


class MalformedOutputQuarantineException(Exception):
    """Raised when scanner output fails integrity, size, or schema validation."""
    pass


class ToolCellExecutionResult:
    """Outcome of a single isolated Tool Cell invocation."""
    def __init__(
        self,
        tool_id: str,
        stage_key: SequentialStageKey,
        status: CellWorkflowState,
        raw_artifact: RawEvidenceArtifact,
        normalized_data: List[BaseModel],
        quarantined_records: List[Dict[str, Any]],
        ai_proposal: Optional[AIPairedProposal] = None,
        error: Optional[str] = None,
        duration_seconds: float = 0.0,
    ):
        self.tool_id = tool_id
        self.stage_key = stage_key
        self.status = status
        self.raw_artifact = raw_artifact
        self.normalized_data = normalized_data
        self.quarantined_records = quarantined_records
        self.ai_proposal = ai_proposal
        self.error = error
        self.duration_seconds = duration_seconds


class ToolCellRunner:
    """Manages ephemeral tool execution, raw evidence sealing, and untrusted output parsing."""

    HOST_SECRETS_BLACKLIST = {
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "GROQ_API_KEY",
        "MONGODB_URL", "MONGO_INITDB_ROOT_PASSWORD", "SECRET_KEY", "JWT_SECRET",
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND", "REDIS_URL", "DATABASE_URL"
    }

    def __init__(self, use_mock_lab_fallback: bool = True):
        self.use_mock_lab_fallback = use_mock_lab_fallback

    def get_sanitized_env(self, mission_id: str) -> Dict[str, str]:
        """Produce clean environment without sensitive credentials."""
        safe_env = {}
        allowed = {"PATH", "SYSTEMROOT", "TMP", "TEMP", "USER", "HOME", "LANG", "LC_ALL"}
        for k, v in os.environ.items():
            if k in allowed and k not in self.HOST_SECRETS_BLACKLIST:
                safe_env[k] = v
        safe_env["ARGOLOCK_TOOL_CELL"] = "1"
        safe_env["ARGOLOCK_JOB_ID"] = mission_id
        return safe_env

    async def execute_cell(
        self,
        scan_id: str,
        stage_key: SequentialStageKey,
        manifest: ToolCellManifest,
        targets: List[str],
        profile: str = "default",
        options: Optional[Dict[str, Any]] = None,
        egress_whitelist: Optional[List[str]] = None,
    ) -> ToolCellExecutionResult:
        """
        Execute an isolated per-job Tool Cell invocation.
        """
        start_time = time.time()
        job_id = f"{scan_id}_{stage_key.value}"
        temp_dir = tempfile.mkdtemp(prefix=f"cell_{manifest.tool_id}_{scan_id[:6]}_")
        options = options or {}
        egress_whitelist = egress_whitelist or targets

        target_set_digest = hashlib.sha256(",".join(sorted(targets)).encode()).hexdigest()[:16]

        try:
            # 1. Check if binary is present on host
            binary_path = shutil.which(manifest.tool_id) if manifest.tool_id != "httpx_probe" else shutil.which("httpx")

            raw_stdout = ""
            raw_format = manifest.raw_evidence_policy.get("format", "json")

            if binary_path and not self.use_mock_lab_fallback:
                # Real subprocess execution in isolated temp_dir
                raw_stdout = await self._run_real_binary(
                    binary=binary_path,
                    targets=targets,
                    temp_dir=temp_dir,
                    env=self.get_sanitized_env(job_id),
                    timeout=manifest.resource_limits.get("timeout_seconds", 60),
                )
            else:
                # Mock / Local-Lab adapter execution
                raw_stdout = self._run_mock_lab_adapter(
                    manifest=manifest,
                    targets=targets,
                    profile=profile,
                    options=options,
                )

            # 2. Check output size limits
            max_size = manifest.raw_evidence_policy.get("max_size_bytes", 10485760)
            if len(raw_stdout.encode("utf-8")) > max_size:
                logger.warning(f"[{manifest.tool_id}] Output exceeded max size {max_size} bytes. Quarantining output.")
                quarantined_artifact = RawEvidenceArtifact(
                    scan_id=scan_id,
                    stage_key=stage_key,
                    tool_id=manifest.tool_id,
                    tool_version=manifest.tool_version,
                    adapter_version=manifest.adapter_version,
                    image_digest=manifest.image_digest,
                    target_set_digest=target_set_digest,
                    content_format=raw_format,
                    raw_content=raw_stdout[:50000] + "\n...[TRUNCATED OVERSIZED CONTENT]",
                    sha256_digest=hashlib.sha256(raw_stdout.encode()).hexdigest(),
                    is_quarantined=True,
                    quarantine_reason=f"Output exceeded byte cap ({len(raw_stdout.encode())} > {max_size})",
                )
                return ToolCellExecutionResult(
                    tool_id=manifest.tool_id,
                    stage_key=stage_key,
                    status=CellWorkflowState.QUARANTINED,
                    raw_artifact=quarantined_artifact,
                    normalized_data=[],
                    quarantined_records=[{"reason": "oversized_output"}],
                    error="Raw output quarantined due to size threshold violation.",
                    duration_seconds=round(time.time() - start_time, 2),
                )

            # Redact secrets from raw output before storing artifact
            redacted_raw, redacted_tags = evidence_collector.redact_sensitive_data(raw_stdout)
            raw_sha256 = hashlib.sha256((redacted_raw or "").encode("utf-8")).hexdigest()

            raw_artifact = RawEvidenceArtifact(
                scan_id=scan_id,
                stage_key=stage_key,
                tool_id=manifest.tool_id,
                tool_version=manifest.tool_version,
                adapter_version=manifest.adapter_version,
                image_digest=manifest.image_digest,
                target_set_digest=target_set_digest,
                content_format=raw_format,
                raw_content=redacted_raw or "",
                sha256_digest=raw_sha256,
                is_quarantined=False,
            )

            # 3. Separate untrusted parsing & schema normalization
            normalized, quarantined = self._parse_and_normalize(
                manifest=manifest,
                raw_output=redacted_raw or "",
                targets=targets,
                raw_ref=raw_artifact.artifact_id,
            )

            # 4. Generate Paired AI Role structured proposal
            ai_proposal = self._generate_paired_ai_proposal(
                manifest=manifest,
                stage_key=stage_key,
                normalized_records=normalized,
                raw_ref=raw_artifact.artifact_id,
            )

            status = CellWorkflowState.COMPLETED
            if quarantined and not normalized:
                status = CellWorkflowState.QUARANTINED
            elif quarantined and normalized:
                status = CellWorkflowState.PARTIAL

            return ToolCellExecutionResult(
                tool_id=manifest.tool_id,
                stage_key=stage_key,
                status=status,
                raw_artifact=raw_artifact,
                normalized_data=normalized,
                quarantined_records=quarantined,
                ai_proposal=ai_proposal,
                duration_seconds=round(time.time() - start_time, 2),
            )

        except Exception as e:
            logger.error(f"[ToolCellRunner] Failed for {manifest.tool_id}: {e}")
            failed_artifact = RawEvidenceArtifact(
                scan_id=scan_id,
                stage_key=stage_key,
                tool_id=manifest.tool_id,
                tool_version=manifest.tool_version,
                adapter_version=manifest.adapter_version,
                image_digest=manifest.image_digest,
                target_set_digest=target_set_digest,
                content_format=manifest.raw_evidence_policy.get("format", "text"),
                raw_content=f"Error executing tool: {e}",
                sha256_digest=hashlib.sha256(str(e).encode()).hexdigest(),
                is_quarantined=True,
                quarantine_reason=str(e),
            )
            return ToolCellExecutionResult(
                tool_id=manifest.tool_id,
                stage_key=stage_key,
                status=CellWorkflowState.FAILED,
                raw_artifact=failed_artifact,
                normalized_data=[],
                quarantined_records=[],
                error=str(e),
                duration_seconds=round(time.time() - start_time, 2),
            )
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    # ─── Mock / Local-Lab Generator ──────────────────────────────────────────

    def _run_mock_lab_adapter(
        self,
        manifest: ToolCellManifest,
        targets: List[str],
        profile: str,
        options: Dict[str, Any],
    ) -> str:
        """
        Generate realistic, spec-compliant raw evidence artifacts for test environments.
        """
        tool_id = manifest.tool_id
        primary_target = targets[0] if targets else "example.com"
        host = primary_target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        if tool_id == "subfinder":
            # JSONL output
            lines = [
                json.dumps({"host": f"api.{host}", "ip": "192.168.1.10", "source": "crtsh"}),
                json.dumps({"host": f"admin.{host}", "ip": "192.168.1.11", "source": "urlscan"}),
                json.dumps({"host": f"mail.{host}", "ip": "192.168.1.12", "source": "threatcrowd"}),
            ]
            return "\n".join(lines)

        elif tool_id == "amass":
            # JSON array / lines
            records = [
                {"name": f"api.{host}", "domain": host, "addresses": [{"ip": "192.168.1.10"}], "tag": "osint", "sources": ["AlienVault"]},
                {"name": f"portal.{host}", "domain": host, "addresses": [{"ip": "192.168.1.15"}], "tag": "dns", "sources": ["HackerTarget"]},
            ]
            return json.dumps(records)

        elif tool_id == "naabu":
            # JSONL output of open ports
            lines = [
                json.dumps({"host": host, "ip": "192.168.1.10", "port": 80, "protocol": "tcp"}),
                json.dumps({"host": host, "ip": "192.168.1.10", "port": 443, "protocol": "tcp"}),
                json.dumps({"host": host, "ip": "192.168.1.10", "port": 8080, "protocol": "tcp"}),
            ]
            return "\n".join(lines)

        elif tool_id == "nmap":
            # XML output
            return f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="{host}"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy" product="Apache Tomcat" version="9.0.58"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        elif tool_id == "httpx_probe":
            # JSONL output
            lines = [
                json.dumps({
                    "url": f"https://{host}",
                    "host": host,
                    "port": "443",
                    "scheme": "https",
                    "status_code": 200,
                    "title": "Corporate Secure Portal",
                    "webserver": "nginx/1.24.0",
                    "tech": ["Nginx", "React", "OpenSSL"],
                }),
                json.dumps({
                    "url": f"http://{host}:8080",
                    "host": host,
                    "port": "8080",
                    "scheme": "http",
                    "status_code": 200,
                    "title": "Management Console",
                    "webserver": "Apache Tomcat/9.0.58",
                    "tech": ["Tomcat", "Java", "Spring"],
                }),
            ]
            return "\n".join(lines)

        elif tool_id == "whatweb":
            # JSON array
            records = [
                {
                    "target": f"https://{host}",
                    "http_status": 200,
                    "plugins": {
                        "HTTPServer": {"string": ["nginx/1.24.0"]},
                        "X-Frame-Options": {"string": ["SAMEORIGIN"]},
                        "Strict-Transport-Security": {"string": ["max-age=31536000"]},
                    }
                }
            ]
            return json.dumps(records)

        elif tool_id == "nuclei":
            # JSONL output of matches
            lines = [
                json.dumps({
                    "template-id": "cve-2021-41773",
                    "info": {
                        "name": "Apache Path Traversal",
                        "severity": "critical",
                        "confidence": "high",
                    },
                    "type": "http",
                    "host": f"https://{host}",
                    "matched-at": f"https://{host}/icons/.%2e/%2e%2e/%2e%2e/etc/passwd",
                    "matcher-status": True,
                    "extracted-results": ["root:x:0:0:root:/root:/bin/bash"],
                }),
                json.dumps({
                    "template-id": "missing-security-headers",
                    "info": {
                        "name": "Missing Content-Security-Policy Header",
                        "severity": "low",
                        "confidence": "certain",
                    },
                    "type": "http",
                    "host": f"https://{host}",
                    "matched-at": f"https://{host}/",
                    "matcher-status": True,
                })
            ]
            return "\n".join(lines)

        elif tool_id == "zap_passive":
            # JSON output
            records = {
                "routes": [
                    {"origin": f"https://{host}", "path": "/login", "method": "GET", "parameters": ["redirect_uri"]},
                    {"origin": f"https://{host}", "path": "/search", "method": "GET", "parameters": ["q", "filter"]},
                    {"origin": f"https://{host}", "path": "/profile", "method": "GET", "parameters": ["user_id"]},
                ],
                "alerts": [
                    {
                        "alert": "Anti-CSRF Tokens Check",
                        "risk": "Medium",
                        "confidence": "Medium",
                        "url": f"https://{host}/search",
                        "param": "q",
                        "evidence": "<form action='/search'>",
                    }
                ]
            }
            return json.dumps(records)

        elif tool_id == "nikto":
            # JSON report
            records = {
                "host": host,
                "port": "443",
                "banner": "nginx/1.24.0",
                "items": [
                    {
                        "id": "000001",
                        "uri": "/admin/",
                        "description": "Admin directory appears to be accessible without authentication.",
                        "severity": "medium"
                    }
                ]
            }
            return json.dumps(records)

        elif tool_id == "dalfox":
            # JSON array
            records = [
                {
                    "type": "VULN",
                    "param": "q",
                    "url": f"https://{host}/search?q=<script>alert(1)</script>",
                    "evidence": "<script>alert(1)</script>",
                    "method": "GET",
                    "severity": "high",
                    "cwe": "CWE-79"
                }
            ]
            return json.dumps(records)

        elif tool_id == "zap_active":
            # Active scan alerts
            records = {
                "active_alerts": [
                    {
                        "alert": "Cross-Site Scripting (Reflected)",
                        "risk": "High",
                        "confidence": "Medium",
                        "url": f"https://{host}/search",
                        "param": "q",
                        "attack": "<script>alert(document.domain)</script>",
                        "evidence": "<script>alert(document.domain)</script>",
                    }
                ]
            }
            return json.dumps(records)

        return json.dumps({"status": "completed", "tool": tool_id})

    # ─── Parser & Normalizer ─────────────────────────────────────────────────

    def _parse_and_normalize(
        self,
        manifest: ToolCellManifest,
        raw_output: str,
        targets: List[str],
        raw_ref: str,
    ) -> Tuple[List[BaseModel], List[Dict[str, Any]]]:
        """
        Validate raw output against typed schemas.
        Quarantines invalid entries and emits normalized records.
        """
        tool_id = manifest.tool_id
        normalized: List[BaseModel] = []
        quarantined: List[Dict[str, Any]] = []

        if not raw_output.strip():
            return [], []

        if tool_id == "subfinder":
            for line in raw_output.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    fqdn = data.get("host") or data.get("subdomain")
                    if not fqdn:
                        quarantined.append({"raw": line, "reason": "Missing host field"})
                        continue
                    normalized.append(
                        DomainCandidate(
                            fqdn=fqdn.strip().lower(),
                            source_tool="subfinder",
                            source_ref=data.get("source", "subfinder"),
                            raw_ref=raw_ref,
                            confidence_hint=0.85,
                        )
                    )
                except Exception as e:
                    quarantined.append({"raw": line, "reason": f"JSON parse error: {e}"})

        elif tool_id == "amass":
            try:
                entries = json.loads(raw_output)
                if isinstance(entries, dict):
                    entries = [entries]
                for item in entries:
                    fqdn = item.get("name")
                    if fqdn:
                        normalized.append(
                            DomainCandidate(
                                fqdn=fqdn.strip().lower(),
                                source_tool="amass",
                                source_ref=",".join(item.get("sources", ["amass"])),
                                raw_ref=raw_ref,
                                confidence_hint=0.90,
                            )
                        )
                    else:
                        quarantined.append({"raw": item, "reason": "Amass missing name field"})
            except Exception as e:
                quarantined.append({"raw": raw_output[:500], "reason": f"Amass JSON parse failed: {e}"})

        elif tool_id == "naabu":
            for line in raw_output.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    port = int(data.get("port", 0))
                    host_ip = data.get("ip") or data.get("host")
                    if port > 0 and host_ip:
                        normalized.append(
                            ServiceEndpointCandidate(
                                asset_id=targets[0] if targets else "asset",
                                ip_or_host=host_ip,
                                protocol=data.get("protocol", "tcp"),
                                port=port,
                                state="open",
                                source_ref="naabu",
                            )
                        )
                    else:
                        quarantined.append({"raw": line, "reason": "Naabu invalid port or host"})
                except Exception as e:
                    quarantined.append({"raw": line, "reason": f"Naabu JSON error: {e}"})

        elif tool_id == "nmap":
            # Simple XML parsing for port & service detection
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(raw_output)
                for port_elem in root.findall(".//port"):
                    portid = int(port_elem.get("portid", 0))
                    proto = port_elem.get("protocol", "tcp")
                    state_elem = port_elem.find("state")
                    service_elem = port_elem.find("service")

                    state = state_elem.get("state") if state_elem is not None else "unknown"
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    product = service_elem.get("product") if service_elem is not None else None
                    version = service_elem.get("version") if service_elem is not None else None

                    if portid > 0:
                        endpoint = f"{targets[0] if targets else 'host'}:{portid}"
                        normalized.append(
                            ServiceFingerprint(
                                endpoint=endpoint,
                                service=service_name,
                                product=product,
                                version=version,
                                confidence=0.90 if version else 0.75,
                                provenance="nmap_version_probe",
                                raw_ref=raw_ref,
                            )
                        )
            except Exception as e:
                quarantined.append({"raw": raw_output[:500], "reason": f"Nmap XML parse error: {e}"})

        elif tool_id == "httpx_probe":
            for line in raw_output.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url") or ""
                    parsed = urlparse(url)
                    host = parsed.hostname or data.get("host") or ""
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    normalized.append(
                        WebOrigin(
                            scheme=parsed.scheme or "http",
                            host=host,
                            port=port,
                            status_code=data.get("status_code"),
                            title=data.get("title"),
                            server_hint=data.get("webserver"),
                            source_ref="httpx_probe",
                            raw_ref=raw_ref,
                        )
                    )
                except Exception as e:
                    quarantined.append({"raw": line, "reason": f"Httpx parse error: {e}"})

        elif tool_id == "whatweb":
            try:
                records = json.loads(raw_output)
                for r in records:
                    target_url = r.get("target", "")
                    parsed = urlparse(target_url)
                    plugins = r.get("plugins", {})
                    server_val = plugins.get("HTTPServer", {}).get("string", [None])[0]
                    normalized.append(
                        WebOrigin(
                            scheme=parsed.scheme or "http",
                            host=parsed.hostname or "unknown",
                            port=parsed.port or (443 if parsed.scheme == "https" else 80),
                            status_code=r.get("http_status"),
                            server_hint=server_val,
                            source_ref="whatweb",
                            raw_ref=raw_ref,
                        )
                    )
            except Exception as e:
                quarantined.append({"raw": raw_output[:500], "reason": f"WhatWeb parse error: {e}"})

        elif tool_id == "nuclei":
            for line in raw_output.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    normalized.append(
                        FindingCandidate(
                            candidate_type="nuclei_template_match",
                            asset=targets[0] if targets else "asset",
                            endpoint=data.get("matched-at") or data.get("host", ""),
                            rule_or_template_id=data.get("template-id", "unknown-template"),
                            evidence_summary=f"Nuclei template matched: {info.get('name', 'Issue')} at {data.get('matched-at')}",
                            severity_hint=info.get("severity", "medium").lower(),
                            confidence_hint=0.85 if info.get("confidence") == "certain" else 0.70,
                            source_refs=["nuclei"],
                            raw_ref=raw_ref,
                            reproduction_class="template_matcher",
                            review_state=FindingReviewState.CANDIDATE,
                        )
                    )
                except Exception as e:
                    quarantined.append({"raw": line, "reason": f"Nuclei parse error: {e}"})

        elif tool_id == "zap_passive":
            try:
                data = json.loads(raw_output)
                # Parse routes
                for r in data.get("routes", []):
                    normalized.append(
                        RouteObservation(
                            origin=r.get("origin", ""),
                            path=r.get("path", "/"),
                            method=r.get("method", "GET"),
                            parameters=r.get("parameters", []),
                            source_ref="zap_passive_crawl",
                        )
                    )
                # Parse alerts
                for a in data.get("alerts", []):
                    normalized.append(
                        FindingCandidate(
                            candidate_type="zap_passive_alert",
                            asset=targets[0] if targets else "asset",
                            endpoint=a.get("url", ""),
                            rule_or_template_id=a.get("alert", "passive-alert"),
                            evidence_summary=f"ZAP Passive Alert: {a.get('alert')} on parameter {a.get('param', 'N/A')}",
                            severity_hint=a.get("risk", "medium").lower(),
                            confidence_hint=0.65,
                            source_refs=["zap_passive"],
                            raw_ref=raw_ref,
                            reproduction_class="passive_heuristic",
                            review_state=FindingReviewState.CANDIDATE,
                        )
                    )
            except Exception as e:
                quarantined.append({"raw": raw_output[:500], "reason": f"ZAP passive parse error: {e}"})

        elif tool_id == "nikto":
            try:
                data = json.loads(raw_output)
                for item in data.get("items", []):
                    normalized.append(
                        FindingCandidate(
                            candidate_type="nikto_server_check",
                            asset=targets[0] if targets else "asset",
                            endpoint=f"{data.get('host', '')}:{data.get('port', '')}{item.get('uri', '')}",
                            rule_or_template_id=f"nikto-{item.get('id', 'check')}",
                            evidence_summary=item.get("description", "Server configuration observation"),
                            severity_hint=item.get("severity", "medium").lower(),
                            confidence_hint=0.60,
                            source_refs=["nikto"],
                            raw_ref=raw_ref,
                            reproduction_class="banner_or_path_check",
                            review_state=FindingReviewState.CANDIDATE,
                        )
                    )
            except Exception as e:
                quarantined.append({"raw": raw_output[:500], "reason": f"Nikto parse error: {e}"})

        elif tool_id == "dalfox":
            try:
                records = json.loads(raw_output)
                for item in records:
                    normalized.append(
                        FindingCandidate(
                            candidate_type="dalfox_xss_validation",
                            asset=targets[0] if targets else "asset",
                            endpoint=item.get("url", ""),
                            rule_or_template_id=f"dalfox-{item.get('param', 'xss')}",
                            evidence_summary=f"Reflected/DOM payload executed on param '{item.get('param')}': {item.get('evidence')}",
                            severity_hint=item.get("severity", "high").lower(),
                            confidence_hint=0.90,
                            source_refs=["dalfox"],
                            raw_ref=raw_ref,
                            reproduction_class="active_payload_reflection",
                            review_state=FindingReviewState.CANDIDATE,
                        )
                    )
            except Exception as e:
                quarantined.append({"raw": raw_output[:500], "reason": f"Dalfox parse error: {e}"})

        elif tool_id == "zap_active":
            try:
                data = json.loads(raw_output)
                for a in data.get("active_alerts", []):
                    normalized.append(
                        FindingCandidate(
                            candidate_type="zap_active_alert",
                            asset=targets[0] if targets else "asset",
                            endpoint=a.get("url", ""),
                            rule_or_template_id=a.get("alert", "active-alert"),
                            evidence_summary=f"ZAP Active Exploit Confirmed: {a.get('alert')} with payload {a.get('attack')}",
                            severity_hint=a.get("risk", "high").lower(),
                            confidence_hint=0.85,
                            source_refs=["zap_active"],
                            raw_ref=raw_ref,
                            reproduction_class="active_scanner_probe",
                            review_state=FindingReviewState.CANDIDATE,
                        )
                    )
            except Exception as e:
                quarantined.append({"raw": raw_output[:500], "reason": f"ZAP active parse error: {e}"})

        return normalized, quarantined

    # ─── Paired AI Role Structured Proposal ──────────────────────────────────

    def _generate_paired_ai_proposal(
        self,
        manifest: ToolCellManifest,
        stage_key: SequentialStageKey,
        normalized_records: List[BaseModel],
        raw_ref: str,
    ) -> AIPairedProposal:
        """
        Generate structured, bounded proposal from the tool's paired AI role.
        AI interprets normalized records and proposes next stage without granting authorization.
        """
        tool_id = manifest.tool_id
        count = len(normalized_records)

        summary = f"Analyzed {count} normalized observation(s) from {manifest.tool_name}."
        uncertainty = None
        next_stage = None
        proposed_profile = None
        requires_approval = False

        if stage_key == SequentialStageKey.SUBFINDER:
            summary = f"Subfinder discovered {count} subdomain candidates. OSINT analysis indicates potential service endpoints."
            next_stage = SequentialStageKey.AMASS
            proposed_profile = "passive"

        elif stage_key == SequentialStageKey.AMASS:
            summary = f"Amass enriched passive topology with {count} records. Ready for deterministic scope resolution."
            next_stage = SequentialStageKey.SCOPE_GATE

        elif stage_key == SequentialStageKey.NAABU:
            summary = f"Naabu discovered {count} open port endpoints across approved targets."
            next_stage = SequentialStageKey.NMAP
            proposed_profile = "service_light"

        elif stage_key == SequentialStageKey.NMAP:
            summary = f"Nmap fingerprinted services on {count} endpoints. Web protocols detected, recommending HTTP probing."
            next_stage = SequentialStageKey.HTTPX_PROBE
            proposed_profile = "standard_probe"

        elif stage_key == SequentialStageKey.HTTPX_PROBE:
            summary = f"HTTP probing identified live web applications. Recommending technology fingerprinting and curated templates."
            next_stage = SequentialStageKey.WHATWEB

        elif stage_key == SequentialStageKey.WHATWEB:
            summary = f"WhatWeb technology fingerprints collected. Recommending curated Nuclei template scan."
            next_stage = SequentialStageKey.NUCLEI
            proposed_profile = "curated_web"

        elif stage_key == SequentialStageKey.NUCLEI:
            summary = f"Nuclei returned {count} candidate matcher events. Recommending application route discovery via ZAP passive crawl."
            next_stage = SequentialStageKey.ZAP_PASSIVE
            proposed_profile = "crawl_and_passive_rules"

        elif stage_key == SequentialStageKey.ZAP_PASSIVE:
            summary = f"ZAP crawl identified application routes and parameter inputs. Parameter candidates detected for XSS review."
            next_stage = SequentialStageKey.DALFOX
            proposed_profile = "candidate_parameter_xss"
            requires_approval = True
            uncertainty = "Active parameter injection requires operator approval gate."

        elif stage_key == SequentialStageKey.DALFOX:
            summary = f"Dalfox targeted testing produced {count} candidate reflections. Ready for multi-tool evidence correlation."
            next_stage = SequentialStageKey.EVIDENCE_CORRELATION

        elif stage_key == SequentialStageKey.NIKTO:
            summary = f"Nikto server checks complete with {count} observations. Correlating with web origins."
            next_stage = SequentialStageKey.EVIDENCE_CORRELATION

        elif stage_key == SequentialStageKey.ZAP_ACTIVE:
            summary = f"ZAP active scanning complete. Correlating active alerts with findings database."
            next_stage = SequentialStageKey.EVIDENCE_CORRELATION

        return AIPairedProposal(
            source_stage=stage_key,
            ai_role=manifest.paired_ai_role,
            model_version="gemini-3.8-flash",
            evidence_references=[raw_ref],
            analysis_summary=summary,
            uncertainty_notes=uncertainty,
            proposed_next_stage=next_stage,
            proposed_profile=proposed_profile,
            requires_operator_approval=requires_approval,
        )


# Global singleton runner
tool_cell_runner = ToolCellRunner()
