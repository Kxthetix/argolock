"""Nuclei tool — template-based vulnerability scanning.

When the ``nuclei`` binary is not installed in PATH or Docker is unavailable,
this module executes a native Python template security probe against the target
to audit sensitive file exposures, CVE path traversals, and HTTP security misconfigurations.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool


# ── Built-in Template Probes ──────────────────────────────────────────────────
_SENSITIVE_TEMPLATE_PROBES: List[Dict[str, Any]] = [
    {
        "path": "/.env",
        "template_id": "env-file-exposure",
        "name": "Environment Configuration File Exposure (.env)",
        "severity": "critical",
        "tags": ["exposure", "config", "env", "credentials"],
        "cvss": 9.1,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"(DB_PASSWORD|SECRET_KEY|AWS_SECRET_ACCESS_KEY|API_KEY|DATABASE_URL|APP_SECRET)=",
        "description": "Publicly accessible .env configuration file revealing sensitive application credentials and secrets.",
    },
    {
        "path": "/.env.local",
        "template_id": "env-local-exposure",
        "name": "Local Environment File Exposure (.env.local)",
        "severity": "critical",
        "tags": ["exposure", "config", "env", "credentials"],
        "cvss": 9.1,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"(DB_PASSWORD|SECRET_KEY|AWS_SECRET_ACCESS_KEY|API_KEY|DATABASE_URL)=",
        "description": "Publicly accessible local environment file revealing database or API credentials.",
    },
    {
        "path": "/.git/HEAD",
        "template_id": "git-head-exposure",
        "name": "Git Source Repository Exposure (.git/HEAD)",
        "severity": "high",
        "tags": ["exposure", "git", "vcs", "source-code"],
        "cvss": 7.5,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"ref: refs/heads/",
        "description": "Exposed .git directory allows remote attackers to dump repository source code and commit history.",
    },
    {
        "path": "/.git/config",
        "template_id": "git-config-exposure",
        "name": "Git Configuration File Exposure (.git/config)",
        "severity": "high",
        "tags": ["exposure", "git", "vcs", "source-code"],
        "cvss": 7.5,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"\[core\]",
        "description": "Exposed .git/config revealing repository configuration and remote repository URLs.",
    },
    {
        "path": "/backup.sql",
        "template_id": "sql-dump-exposure",
        "name": "Database Backup SQL Dump Exposure",
        "severity": "high",
        "tags": ["exposure", "backup", "database", "sql"],
        "cvss": 7.5,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"(CREATE TABLE|INSERT INTO|DROP TABLE)",
        "description": "Exposed database SQL backup file containing schema and records.",
    },
    {
        "path": "/dump.sql",
        "template_id": "sql-dump-exposure",
        "name": "Database Dump File Exposure",
        "severity": "high",
        "tags": ["exposure", "backup", "database", "sql"],
        "cvss": 7.5,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"(CREATE TABLE|INSERT INTO|DROP TABLE)",
        "description": "Exposed database dump file containing table schemas and records.",
    },
    {
        "path": "/phpinfo.php",
        "template_id": "phpinfo-disclosure",
        "name": "PHP Configuration Information Disclosure (phpinfo)",
        "severity": "medium",
        "tags": ["exposure", "php", "misconfig", "info-leak"],
        "cvss": 5.3,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"PHP Version|Configuration File \(php\.ini\) Path|Directive",
        "description": "phpinfo() diagnostic page is publicly accessible, leaking full PHP and web server configuration.",
    },
    {
        "path": "/server-status",
        "template_id": "apache-server-status",
        "name": "Apache HTTP Server Status Page Exposed",
        "severity": "medium",
        "tags": ["exposure", "apache", "status", "info-leak"],
        "cvss": 5.3,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"Apache Server Status|Server Version:|Current Time:",
        "description": "Apache server-status page exposes real-time requests, client IPs, and server metrics.",
    },
    {
        "path": "/actuator/health",
        "template_id": "springboot-actuator-health",
        "name": "Spring Boot Actuator Health Endpoint Exposed",
        "severity": "low",
        "tags": ["exposure", "springboot", "actuator", "discovery"],
        "cvss": 3.1,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r'\{"status":"(UP|DOWN|UNKNOWN)"',
        "description": "Spring Boot Actuator health endpoint is publicly accessible without authentication.",
    },
    {
        "path": "/actuator/env",
        "template_id": "springboot-actuator-env",
        "name": "Spring Boot Actuator Environment Endpoint Exposed",
        "severity": "high",
        "tags": ["exposure", "springboot", "actuator", "env", "secrets"],
        "cvss": 7.5,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r'("propertySources":|"activeProfiles":)',
        "description": "Spring Boot Actuator env endpoint exposes environment variables and configuration properties.",
    },
    {
        "path": "/metrics",
        "template_id": "prometheus-metrics-exposed",
        "name": "Prometheus Metrics Endpoint Exposed",
        "severity": "medium",
        "tags": ["exposure", "metrics", "prometheus", "info-leak"],
        "cvss": 5.3,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r"(go_goroutines|http_requests_total|process_cpu_seconds_total)",
        "description": "Prometheus application metrics endpoint is exposed without authentication.",
    },
    {
        "path": "/swagger.json",
        "template_id": "swagger-api-docs-exposure",
        "name": "Swagger API Documentation JSON Exposed",
        "severity": "low",
        "tags": ["exposure", "swagger", "api", "discovery"],
        "cvss": 2.5,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r'("swagger":|"openapi":)',
        "description": "Swagger API specification is publicly reachable, detailing internal API routes and schemas.",
    },
    {
        "path": "/openapi.json",
        "template_id": "openapi-spec-exposure",
        "name": "OpenAPI Specification Exposed",
        "severity": "low",
        "tags": ["exposure", "openapi", "api", "discovery"],
        "cvss": 2.5,
        "cve": [],
        "cwe": "CWE-200",
        "pattern": r'("openapi":|"paths":)',
        "description": "OpenAPI specification document is accessible, exposing REST endpoints and parameter schemas.",
    },
    {
        "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "template_id": "CVE-2021-41773",
        "name": "Apache 2.4.49 - Path Traversal & Remote Code Execution",
        "severity": "critical",
        "tags": ["cve", "cve2021", "apache", "rce", "lfi", "traversal"],
        "cvss": 9.8,
        "cve": ["CVE-2021-41773"],
        "cwe": "CWE-22",
        "pattern": r"root:.*:0:0:",
        "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49 allows unauthenticated remote attackers to read arbitrary files.",
    },
]


class NucleiTool(BaseTool):
    name = "nuclei"
    docker_image = settings.nuclei_docker_image

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        severities = options.get("severities", ["critical", "high", "medium"])
        severity_str = ",".join(severities)

        cmd = [
            "nuclei",
            "-target", target,
            "-severity", severity_str,
            "-jsonl",                   # JSONL output per finding
            "-silent",                  # No banner
            "-no-color",
            "-timeout", "10",           # Per-request timeout
            "-rate-limit", "50",        # Rate limit req/sec
            "-bulk-size", "25",
            "-concurrency", "10",
            "-update-templates",        # Always use latest templates
        ]
        return cmd

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Real HTTP security probe simulating Nuclei template execution."""
        logger.info(f"[nuclei] Running Python template security probe on {target}")
        findings_jsonl: List[str] = []
        base_target = target if target.startswith("http") else f"http://{target}"
        base_parsed = urllib.parse.urlparse(base_target)
        host = base_parsed.netloc.split(":")[0]
        ip_addr = ""
        try:
            import socket
            ip_addr = socket.gethostbyname(host)
        except Exception:
            ip_addr = host

        requested_severities = [s.lower() for s in options.get("severities", ["critical", "high", "medium", "low", "info"])]

        try:
            with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
                # 1. Base Request - Header checks & server banner
                try:
                    resp = client.get(base_target)
                    self._check_base_security(resp, base_target, host, ip_addr, requested_severities, findings_jsonl)
                except httpx.RequestError as exc:
                    logger.warning(f"[nuclei] Base HTTP request failed: {exc}")

                # 2. Sensitive files and path probes
                for probe in _SENSITIVE_TEMPLATE_PROBES:
                    sev = probe["severity"]
                    if requested_severities and sev not in requested_severities:
                        continue
                    probe_url = urllib.parse.urljoin(base_target, probe["path"])
                    try:
                        probe_resp = client.get(probe_url)
                        if probe_resp.status_code == 200 and probe_resp.text:
                            if re.search(probe["pattern"], probe_resp.text, re.IGNORECASE):
                                finding_obj = {
                                    "template-id": probe["template_id"],
                                    "info": {
                                        "name": probe["name"],
                                        "author": ["argolock-scanner"],
                                        "tags": probe["tags"],
                                        "severity": sev,
                                        "description": probe["description"],
                                        "reference": [
                                            f"https://cwe.mitre.org/data/definitions/{probe['cwe'].replace('CWE-', '')}.html"
                                        ] if probe.get("cwe") else [],
                                        "classification": {
                                            "cvss-score": probe["cvss"],
                                            "cve-id": probe["cve"],
                                            "cwe-id": [probe["cwe"]] if probe.get("cwe") else [],
                                        },
                                    },
                                    "type": "http",
                                    "host": host,
                                    "matched-at": probe_url,
                                    "extracted-results": [],
                                    "request": f"GET {probe['path']} HTTP/1.1\nHost: {host}",
                                    "response": f"HTTP/1.1 {probe_resp.status_code} OK\n" + probe_resp.text[:1500],
                                    "ip": ip_addr,
                                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                                    "curl-command": f"curl -s -k '{probe_url}'",
                                }
                                findings_jsonl.append(json.dumps(finding_obj))
                    except httpx.RequestError:
                        continue

        except Exception as exc:
            logger.warning(f"[nuclei] Fallback probe error: {exc}")

        stdout = "\n".join(findings_jsonl)
        return stdout, "", 0

    def _check_base_security(
        self,
        resp: httpx.Response,
        target_url: str,
        host: str,
        ip_addr: str,
        severities: List[str],
        findings_jsonl: List[str],
    ):
        """Audit base response headers and misconfigurations."""
        headers = {k.lower(): v for k, v in resp.headers.items()}
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Missing Content-Security-Policy
        if "content-security-policy" not in headers and ("medium" in severities or not severities):
            findings_jsonl.append(json.dumps({
                "template-id": "http-missing-security-headers-csp",
                "info": {
                    "name": "Missing Content-Security-Policy Header",
                    "author": ["argolock-scanner"],
                    "tags": ["headers", "misconfig", "csp", "generic"],
                    "severity": "medium",
                    "description": "The Content-Security-Policy header is missing, reducing browser defenses against Cross-Site Scripting (XSS) and data injection.",
                    "reference": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    "classification": {
                        "cvss-score": 5.3,
                        "cwe-id": ["CWE-693"],
                    },
                },
                "type": "http",
                "host": host,
                "matched-at": target_url,
                "request": f"GET / HTTP/1.1\nHost: {host}",
                "response": f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                "ip": ip_addr,
                "timestamp": ts,
                "curl-command": f"curl -s -I -k '{target_url}'",
            }))

        # Missing Strict-Transport-Security on HTTPS
        if target_url.startswith("https") and "strict-transport-security" not in headers and ("medium" in severities or not severities):
            findings_jsonl.append(json.dumps({
                "template-id": "http-missing-security-headers-hsts",
                "info": {
                    "name": "Missing Strict-Transport-Security (HSTS) Header",
                    "author": ["argolock-scanner"],
                    "tags": ["headers", "hsts", "tls", "generic"],
                    "severity": "medium",
                    "description": "Strict-Transport-Security HTTP header is missing, allowing potential SSL stripping attacks.",
                    "reference": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                    "classification": {
                        "cvss-score": 5.3,
                        "cwe-id": ["CWE-319"],
                    },
                },
                "type": "http",
                "host": host,
                "matched-at": target_url,
                "request": f"GET / HTTP/1.1\nHost: {host}",
                "response": f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                "ip": ip_addr,
                "timestamp": ts,
                "curl-command": f"curl -s -I -k '{target_url}'",
            }))

        # Missing X-Frame-Options
        if "x-frame-options" not in headers and ("medium" in severities or not severities):
            findings_jsonl.append(json.dumps({
                "template-id": "http-missing-security-headers-xfo",
                "info": {
                    "name": "Missing X-Frame-Options Header",
                    "author": ["argolock-scanner"],
                    "tags": ["headers", "clickjacking", "generic"],
                    "severity": "medium",
                    "description": "X-Frame-Options header is not configured, leaving the site susceptible to Clickjacking framing attacks.",
                    "reference": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                    "classification": {
                        "cvss-score": 5.3,
                        "cwe-id": ["CWE-1021"],
                    },
                },
                "type": "http",
                "host": host,
                "matched-at": target_url,
                "request": f"GET / HTTP/1.1\nHost: {host}",
                "response": f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                "ip": ip_addr,
                "timestamp": ts,
                "curl-command": f"curl -s -I -k '{target_url}'",
            }))

        # Server Banner Disclosure
        server_header = headers.get("server") or headers.get("x-powered-by")
        if server_header and ("info" in severities or "low" in severities or not severities):
            findings_jsonl.append(json.dumps({
                "template-id": "server-banner-disclosure",
                "info": {
                    "name": "Web Server Version Banner Disclosure",
                    "author": ["argolock-scanner"],
                    "tags": ["disclosure", "server", "info-leak"],
                    "severity": "info",
                    "description": f"The web server exposes its version banner ({server_header}) in HTTP response headers.",
                    "reference": ["https://owasp.org/www-project-top-ten/"],
                    "classification": {
                        "cvss-score": 0.0,
                        "cwe-id": ["CWE-200"],
                    },
                },
                "type": "http",
                "host": host,
                "matched-at": target_url,
                "extracted-results": [server_header],
                "request": f"GET / HTTP/1.1\nHost: {host}",
                "response": f"HTTP/1.1 {resp.status_code}\nServer: {server_header}",
                "ip": ip_addr,
                "timestamp": ts,
                "curl-command": f"curl -s -I -k '{target_url}'",
            }))

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        """Parse Nuclei JSONL output — each line is a finding."""
        findings = []

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                parsed = {
                    "template_id": finding.get("template-id", ""),
                    "template_name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", "info"),
                    "description": finding.get("info", {}).get("description", ""),
                    "tags": finding.get("info", {}).get("tags", []),
                    "classification": finding.get("info", {}).get("classification", {}),
                    "matched_at": finding.get("matched-at", target),
                    "endpoint": finding.get("matched-at", target),
                    "extracted_results": finding.get("extracted-results", []),
                    "request": finding.get("request", ""),
                    "response": finding.get("response", "")[:2000],  # Cap response size
                    "curl_command": finding.get("curl-command", ""),
                    "matcher_name": finding.get("matcher-name", ""),
                    "type": finding.get("type", ""),
                    "host": finding.get("host", target),
                    "ip": finding.get("ip", ""),
                    "timestamp": finding.get("timestamp", ""),
                    "references": finding.get("info", {}).get("reference", []),
                    "cvss_score": self._extract_cvss(finding),
                    "cve_ids": self._extract_cves(finding),
                }
                findings.append(parsed)
            except json.JSONDecodeError:
                logger.warning(f"Nuclei: failed to parse JSON line: {line[:200]}")
                continue

        return {
            "findings": findings,
            "total": len(findings),
        }

    def _extract_cvss(self, finding: dict) -> float:
        """Extract CVSS score from Nuclei finding."""
        classification = finding.get("info", {}).get("classification", {})
        if "cvss-score" in classification:
            try:
                return float(classification["cvss-score"])
            except (ValueError, TypeError):
                pass
        # Map severity to default score
        sev_map = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.5, "info": 0.0}
        sev = finding.get("info", {}).get("severity", "info").lower()
        return sev_map.get(sev, 0.0)

    def _extract_cves(self, finding: dict) -> List[str]:
        """Extract CVE IDs from Nuclei finding."""
        classification = finding.get("info", {}).get("classification", {})
        cves = classification.get("cve-id", [])
        if isinstance(cves, str):
            return [cves]
        return cves or []
