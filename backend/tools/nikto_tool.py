"""Nikto tool — web server vulnerability scanner.

When the ``nikto`` binary is not installed, this module performs a real
HTTP-based security probe against the target: checks for missing security
headers, exposed sensitive paths, and common web server misconfigurations.
All results are from actual live network probes — no fake data.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool


# ── Paths to probe for exposure ───────────────────────────────────────────────
_SENSITIVE_PATHS = [
    ("/.git/HEAD",         "Git repository exposed — source code may be accessible"),
    ("/.env",              "Environment file exposed — may contain secrets and credentials"),
    ("/.env.local",        "Local environment file exposed"),
    ("/.env.backup",       "Backup environment file exposed"),
    ("/robots.txt",        "robots.txt found — review for disallowed sensitive paths"),
    ("/sitemap.xml",       "sitemap.xml found"),
    ("/.htaccess",         "Apache .htaccess file accessible"),
    ("/server-status",     "Apache server-status page may be accessible"),
    ("/phpinfo.php",       "phpinfo() page exposed — reveals server configuration"),
    ("/info.php",          "PHP info page accessible"),
    ("/test.php",          "PHP test file exposed"),
    ("/debug.php",         "PHP debug file exposed"),
    ("/admin/",            "Admin panel directory found"),
    ("/administrator/",    "Administrator panel found (Joomla?)"),
    ("/wp-admin/",         "WordPress admin panel detected"),
    ("/wp-login.php",      "WordPress login page accessible"),
    ("/backup/",           "Backup directory may be accessible"),
    ("/backup.zip",        "Backup archive may be downloadable"),
    ("/backup.tar.gz",     "Backup archive may be downloadable"),
    ("/config.php",        "PHP configuration file accessible"),
    ("/config.yml",        "YAML configuration file accessible"),
    ("/config.yaml",       "YAML configuration file accessible"),
    ("/database.sql",      "SQL dump file may be accessible"),
    ("/dump.sql",          "SQL dump file may be accessible"),
    ("/web.config",        "ASP.NET web.config accessible"),
    ("/crossdomain.xml",   "Flash crossdomain policy accessible"),
    ("/.well-known/security.txt", "Security policy file found"),
]

# ── Security headers that should be present ───────────────────────────────────
_REQUIRED_SECURITY_HEADERS = [
    ("X-Frame-Options",            "high",   "Missing X-Frame-Options header. Site may be vulnerable to Clickjacking."),
    ("Content-Security-Policy",    "medium", "Missing Content-Security-Policy header. XSS mitigation is weakened."),
    ("X-Content-Type-Options",     "low",    "Missing X-Content-Type-Options header. MIME-sniffing attacks possible."),
    ("X-XSS-Protection",           "low",    "Missing X-XSS-Protection header."),
    ("Referrer-Policy",            "info",   "Missing Referrer-Policy header."),
    ("Permissions-Policy",         "info",   "Missing Permissions-Policy header."),
]

_HSTS_HEADER = ("Strict-Transport-Security", "medium",
                 "Missing HSTS header. HTTPS is not enforced via HTTP header.")


class NiktoTool(BaseTool):
    name = "nikto"
    docker_image = settings.nikto_docker_image

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        return [
            "nikto",
            "-h", target,
            "-Format", "json",
            "-output", "/dev/stdout",
            "-nointeractive",
            "-Tuning", "1234567890",   # All checks
            "-timeout", "10",
        ]

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Real HTTP probe: checks security headers and exposed sensitive paths."""
        logger.info(f"[nikto] Running Python HTTP security probe on {target}")
        findings: List[Dict[str, Any]] = []

        try:
            with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
                # Base request to check headers
                resp = client.get(target)
                self._check_security_headers(resp, target, findings)
                self._check_server_version(resp, target, findings)
                self._check_cookie_security(resp, target, findings)
                # Probe sensitive paths
                self._probe_paths(client, target, findings)
        except httpx.RequestError as exc:
            logger.warning(f"[nikto] HTTP probe error: {exc}")
            findings.append({
                "id": "ERR-001",
                "method": "GET",
                "url": target,
                "msg": f"Target unreachable during probe: {exc}",
                "references": {"url": []},
            })

        result = {"vulnerabilities": findings}
        stdout = json.dumps(result)
        return stdout, "", 0

    def _check_security_headers(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        headers_lc = {k.lower(): v for k, v in resp.headers.items()}

        for header, severity, msg in _REQUIRED_SECURITY_HEADERS:
            if header.lower() not in headers_lc:
                findings.append({
                    "id": f"HDR-{header[:6].upper()}",
                    "method": "GET",
                    "url": target,
                    "msg": msg,
                    "severity": severity,
                    "references": {"url": [
                        "https://owasp.org/www-project-secure-headers/"
                    ]},
                })

        # HSTS only matters for HTTPS targets
        if target.startswith("https://"):
            header, severity, msg = _HSTS_HEADER
            if header.lower() not in headers_lc:
                findings.append({
                    "id": "HDR-HSTS",
                    "method": "GET",
                    "url": target,
                    "msg": msg,
                    "severity": severity,
                    "references": {"url": [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                    ]},
                })

    def _check_server_version(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        server = resp.headers.get("server", "")
        if server:
            # Detect version disclosure
            version_pattern = re.search(r"([\d.]+)", server)
            if version_pattern:
                findings.append({
                    "id": "SRV-VER",
                    "method": "GET",
                    "url": target,
                    "msg": f"Server header discloses version: {server}. Version disclosure helps attackers identify vulnerable software.",
                    "severity": "info",
                    "references": {"url": []},
                })

    def _check_cookie_security(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        for cookie in resp.cookies.jar:
            issues = []
            if not cookie.secure and target.startswith("https://"):
                issues.append("missing 'Secure' flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing 'HttpOnly' flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing 'SameSite' attribute")
            if issues:
                findings.append({
                    "id": "COK-SEC",
                    "method": "GET",
                    "url": target,
                    "msg": f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}.",
                    "severity": "medium",
                    "references": {"url": [
                        "https://owasp.org/www-community/HttpOnly"
                    ]},
                })

    def _probe_paths(
        self, client: httpx.Client, base_url: str, findings: List
    ) -> None:
        base = base_url.rstrip("/")
        for path, description in _SENSITIVE_PATHS:
            url = base + path
            try:
                r = client.get(url, timeout=8, follow_redirects=False)
                # 200 or 301/302 to non-login page may indicate exposure
                if r.status_code in (200, 301, 302, 403):
                    status_note = (
                        "accessible" if r.status_code == 200
                        else f"returns {r.status_code}"
                    )
                    severity = "high" if r.status_code == 200 and any(
                        s in path for s in [".git", ".env", "phpinfo", "dump.sql", "backup"]
                    ) else "info"
                    findings.append({
                        "id": f"PATH-{path.replace('/', '_').strip('_')[:15].upper()}",
                        "method": "GET",
                        "url": url,
                        "endpoint": url,
                        "msg": f"{description} — {status_note} (HTTP {r.status_code})",
                        "severity": severity,
                        "references": {"url": []},
                    })
            except httpx.RequestError:
                pass  # Network unreachable on this path — skip silently

    # ── Parse output ──────────────────────────────────────────────────────────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        findings = []

        # Try JSON parsing first
        try:
            json_match = re.search(r'\{.*\}', stdout, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                vulnerabilities = data.get("vulnerabilities", [])
                for v in vulnerabilities:
                    findings.append({
                        "id": v.get("id", ""),
                        "method": v.get("method", "GET"),
                        "url": v.get("url", target),
                        "endpoint": v.get("url", v.get("endpoint", target)),
                        "msg": v.get("msg", ""),
                        "severity": v.get("severity", "info"),
                        "references": v.get("references", {}).get("url", []),
                    })
                return {"findings": findings, "total": len(findings), "target": target}
        except (json.JSONDecodeError, AttributeError):
            pass

        # Fallback: parse text output (real nikto binary)
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith("+") and len(line) > 2:
                finding = {
                    "msg": line[2:].strip(),
                    "endpoint": target,
                    "method": "GET",
                    "id": "",
                    "severity": "info",
                }
                url_match = re.search(r'(/[^\s:]+)', line)
                if url_match:
                    finding["endpoint"] = f"{target.rstrip('/')}{url_match.group(1)}"
                findings.append(finding)

        return {"findings": findings, "total": len(findings), "target": target}
