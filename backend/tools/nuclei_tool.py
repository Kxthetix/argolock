"""Nuclei tool — template-based vulnerability scanning.

When the ``nuclei`` binary is not installed, this module performs a real
HTTP-based template and security probe against the target: checks for exposed
sensitive files, configuration disclosures, misconfigured headers, actuator/debug
endpoints, and common vulnerability indicators.
All results are from actual live network probes — no fake data.
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


# ── Template Probe Definitions ───────────────────────────────────────────────
_SENSITIVE_TEMPLATE_PROBES = [
    # (path, template_id, name, severity, tags, cvss, cve, cwe, match_regex, description)
    (
        "/.env",
        "env-file-exposure",
        "Environment Configuration File Exposure",
        "critical",
        ["exposure", "config", "env", "credentials"],
        9.1,
        [],
        "CWE-200",
        r"(DB_PASSWORD|SECRET_KEY|AWS_SECRET_ACCESS_KEY|API_KEY|DATABASE_URL|APP_SECRET)=",
        "Publicly accessible .env configuration file revealing sensitive secrets and credentials."
    ),
    (
        "/.env.local",
        "env-local-exposure",
        "Local Environment Configuration File Exposure",
        "critical",
        ["exposure", "config", "env", "credentials"],
        9.1,
        [],
        "CWE-200",
        r"(DB_PASSWORD|SECRET_KEY|AWS_SECRET_ACCESS_KEY|API_KEY|DATABASE_URL)=",
        "Publicly accessible local environment file revealing credentials."
    ),
    (
        "/.git/HEAD",
        "git-head-exposure",
        "Git Source Control Repository Exposure",
        "high",
        ["exposure", "git", "vcs", "source-code"],
        7.5,
        [],
        "CWE-200",
        r"ref: refs/heads/",
        "Exposed .git directory allows attackers to download complete source code and commit history."
    ),
    (
        "/.git/config",
        "git-config-exposure",
        "Git Configuration File Exposure",
        "high",
        ["exposure", "git", "vcs", "source-code"],
        7.5,
        [],
        "CWE-200",
        r"\[core\]",
        "Exposed .git/config revealing repository configuration and remote repository URLs."
    ),
    (
        "/backup.sql",
        "sql-dump-exposure",
        "Database SQL Backup Dump Exposure",
        "high",
        ["exposure", "backup", "database", "sql"],
        7.5,
        [],
        "CWE-200",
        r"(CREATE TABLE|INSERT INTO|DROP TABLE)",
        "Exposed database backup dump file containing table schemas and potentially sensitive data."
    ),
    (
        "/dump.sql",
        "sql-dump-exposure",
        "Database SQL Backup Dump Exposure",
        "high",
        ["exposure", "backup", "database", "sql"],
        7.5,
        [],
        "CWE-200",
        r"(CREATE TABLE|INSERT INTO|DROP TABLE)",
        "Exposed database dump file containing table schemas and records."
    ),
    (
        "/database.sql",
        "sql-dump-exposure",
        "Database SQL Backup Dump Exposure",
        "high",
        ["exposure", "backup", "database", "sql"],
        7.5,
        [],
        "CWE-200",
        r"(CREATE TABLE|INSERT INTO|DROP TABLE)",
        "Exposed database dump file containing table schemas."
    ),
    (
        "/phpinfo.php",
        "phpinfo-disclosure",
        "PHP Configuration Information Disclosure (phpinfo)",
        "medium",
        ["exposure", "php", "misconfig", "info-leak"],
        5.3,
        [],
        "CWE-200",
        r"PHP Version|Configuration File \(php\.ini\) Path|Directive",
        "phpinfo() diagnostic page is publicly accessible, leaking full PHP and web server configuration."
    ),
    (
        "/server-status",
        "apache-server-status",
        "Apache HTTP Server Status Page Exposed",
        "medium",
        ["exposure", "apache", "status", "info-leak"],
        5.3,
        [],
        "CWE-200",
        r"Apache Server Status|Server Version:|Current Time:",
        "Apache server-status page exposes real-time requests, client IPs, and server metrics."
    ),
    (
        "/actuator/health",
        "springboot-actuator-health",
        "Spring Boot Actuator Health Endpoint Exposed",
        "low",
        ["exposure", "springboot", "actuator", "discovery"],
        3.1,
        [],
        "CWE-200",
        r'\{"status":"(UP|DOWN|UNKNOWN)"',
        "Spring Boot Actuator health endpoint is publicly accessible without authentication."
    ),
    (
        "/actuator/env",
        "springboot-actuator-env",
        "Spring Boot Actuator Environment Endpoint Exposed",
        "high",
        ["exposure", "springboot", "actuator", "env", "secrets"],
        7.5,
        [],
        "CWE-200",
        r'("propertySources":|"activeProfiles":)',
        "Spring Boot Actuator env endpoint exposes environment variables and configuration properties."
    ),
    (
        "/metrics",
        "prometheus-metrics-exposed",
        "Prometheus Metrics Endpoint Exposed",
        "medium",
        ["exposure", "metrics", "prometheus", "info-leak"],
        5.3,
        [],
        "CWE-200",
        r"(go_goroutines|http_requests_total|process_cpu_seconds_total)",
        "Prometheus application metrics endpoint is exposed without authentication."
    ),
    (
        "/swagger.json",
        "swagger-api-docs-exposure",
        "Swagger API Documentation JSON Exposed",
        "low",
        ["exposure", "swagger", "api", "discovery"],
        2.5,
        [],
        "CWE-200",
        r'("swagger":|"openapi":)',
        "Swagger API specification is publicly reachable, detailing internal API routes and schemas."
    ),
    (
        "/openapi.json",
        "openapi-spec-exposure",
        "OpenAPI Specification Exposed",
        "low",
        ["exposure", "openapi", "api", "discovery"],
        2.5,
        [],
        "CWE-200",
        r'("openapi":|"paths":)',
        "OpenAPI specification document is accessible, exposing REST endpoints and parameter schemas."
    ),
    (
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "CVE-2021-41773",
        "Apache 2.4.49 - Path Traversal & Remote Code Execution",
        "critical",
        ["cve", "cve2021", "apache", "rce", "lfi", "traversal"],
        9.8,
        ["CVE-2021-41773"],
        "CWE-22",
        r"root:.*:0:0:",
        "Path traversal vulnerability in Apache HTTP Server 2.4.49 allows unauthenticated remote attackers to read arbitrary files."
    ),
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
                for path, template_id, name, severity, tags, cvss, cves, cwe, pattern, desc in _SENSITIVE_TEMPLATE_PROBES:
                    if requested_severities and severity not in requested_severities:
                        continue
                    probe_url = urllib.parse.urljoin(base_target, path)
                    try:
                        probe_resp = client.get(probe_url)
                        if probe_resp.status_code == 200 and probe_resp.text:
                            if re.search(pattern, probe_resp.text, re.IGNORECASE):
                                finding_obj = {
                                    "template-id": template_id,
                                    "info": {
                                        "name": name,
                                        "author": ["argolock-scanner"],
                                        "tags": tags,
                                        "severity": severity,
                                        "description": desc,
                                        "reference": [
                                            "https://cwe.mitre.org/data/definitions/" + cwe.replace("CWE-", "") + ".html"
                                        ] if cwe else [],
                                        "classification": {
                                            "cvss-score": cvss,
                                            "cve-id": cves,
                                            "cwe-id": [cwe] if cwe else [],
                                        },
                                    },
                                    "type": "http",
                                    "host": host,
                                    "matched-at": probe_url,
                                    "extracted-results": [],
                                    "request": f"GET {path} HTTP/1.1\nHost: {host}",
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
