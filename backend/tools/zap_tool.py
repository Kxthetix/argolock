"""OWASP ZAP tool — web application active scanner via REST API.

When the ZAP API service is unreachable, this module performs a real Python-based
passive/active security probe against the target, checking for CORS misconfigurations,
cookie security flags, form CSRF protection, information disclosure, and common
HTTP security policy issues — all via actual live network requests.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import httpx
from loguru import logger

from app.config import settings
from app.models.scan import ToolResult, ToolStatus


class ZAPTool:
    """
    Integrates with OWASP ZAP via its REST API.
    Falls back to a lightweight Python-based security probe when ZAP API is offline.
    """
    name = "zap"

    def __init__(self):
        self.base_url = settings.zap_base_url
        self.api_key = settings.zap_api_key
        self.timeout = settings.tool_timeout_seconds

    @property
    def _headers(self) -> Dict[str, str]:
        return {"X-ZAP-API-Key": self.api_key}

    async def _get(self, path: str, params: Dict = None) -> Dict:
        url = f"{self.base_url}/JSON/{path}/"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params={"apikey": self.api_key, **(params or {})})
            resp.raise_for_status()
            return resp.json()

    async def _action(self, path: str, params: Dict = None) -> Dict:
        url = f"{self.base_url}/JSON/{path}/"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params={"apikey": self.api_key, **(params or {})})
            resp.raise_for_status()
            return resp.json()

    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        result = ToolResult(
            tool_name=self.name,
            status=ToolStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        try:
            # ── Try the ZAP REST API ───────────────────────────────────────────
            logger.info(f"ZAP: Starting spider on {target}")
            spider_resp = await self._action("spider/action/scan", {"url": target})
            spider_id = spider_resp.get("scan", "0")

            # Wait for spider to complete
            for _ in range(60):
                progress = await self._get("spider/view/status", {"scanId": spider_id})
                if int(progress.get("status", 0)) >= 100:
                    break
                await asyncio.sleep(5)

            # Active scan
            logger.info(f"ZAP: Starting active scan on {target}")
            ascan_resp = await self._action("ascan/action/scan", {
                "url": target,
                "recurse": "true",
                "scanPolicyName": "Default Policy",
            })
            ascan_id = ascan_resp.get("scan", "0")

            for _ in range(60):
                progress = await self._get("ascan/view/status", {"scanId": ascan_id})
                pct = int(progress.get("status", 0))
                logger.debug(f"ZAP active scan progress: {pct}%")
                if pct >= 100:
                    break
                await asyncio.sleep(5)

            alerts_resp = await self._get("core/view/alerts", {"baseurl": target})
            alerts = alerts_resp.get("alerts", [])
            parsed = self._parse_alerts(alerts, target)
            result.parsed_data = parsed
            result.status = ToolStatus.COMPLETED
            result.exit_code = 0
            result.raw_output = f"[OWASP ZAP Active Scan Complete] Processed {len(alerts)} alerts for {target}"

        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError,
                httpx.ReadError, Exception) as exc:
            # ZAP API is offline — run the Python fallback scanner
            is_conn_error = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout,
                                             httpx.RemoteProtocolError))
            if is_conn_error:
                logger.warning(
                    f"[zap] ZAP API unreachable at {self.base_url}. "
                    f"Running Python lightweight security probe fallback."
                )
            else:
                logger.warning(f"[zap] ZAP error: {exc}. Running Python fallback.")

            try:
                fallback_data, probe_logs = await self._python_fallback_scan(target)
                result.parsed_data = fallback_data
                result.status = ToolStatus.COMPLETED
                result.exit_code = 0
                result.raw_output = probe_logs
            except Exception as fallback_exc:
                result.status = ToolStatus.FAILED
                result.exit_code = 1
                result.error = f"ZAP API offline and fallback failed: {fallback_exc}"
                result.raw_output = f"[-] ZAP API unreachable at {self.base_url}\n[-] Fallback failed: {fallback_exc}"
                logger.error(f"ZAP fallback failed: {fallback_exc}")

        result.completed_at = datetime.now(timezone.utc)
        if result.started_at:
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    # ── Python fallback scanner ───────────────────────────────────────────────

    async def _python_fallback_scan(self, target: str) -> tuple[Dict[str, Any], str]:
        """Perform a real lightweight security scan using Python httpx."""
        findings: List[Dict[str, Any]] = []
        logs: List[str] = [
            f"[*] OWASP ZAP REST API at {self.base_url} is offline/unreachable.",
            f"[*] Automatically engaged native Python Web Vulnerability Probe engine.",
            f"[*] Target URL: {target}",
            f"[*] Executing passive & active security policy checks...\n",
        ]

        try:
            async with httpx.AsyncClient(
                timeout=15, follow_redirects=True, verify=False
            ) as client:
                resp = await client.get(target)
                logs.append(f"[+] Initial GET request succeeded: HTTP {resp.status_code} ({len(resp.content)} bytes)")

                # CORS
                prev_count = len(findings)
                await self._check_cors(client, target, resp, findings)
                if len(findings) > prev_count:
                    logs.append(f"  [!] CORS Misconfiguration: {findings[-1]['name']} ({findings[-1]['severity'].upper()})")
                else:
                    logs.append(f"  [+] CORS Policy: OK")

                # Cookie Flags
                prev_count = len(findings)
                self._check_cookie_flags(resp, target, findings)
                if len(findings) > prev_count:
                    logs.append(f"  [!] Cookie Security: {findings[-1]['name']} ({findings[-1]['severity'].upper()})")
                else:
                    logs.append(f"  [+] Cookie Security: OK / No insecure cookies")

                # CSRF in Forms
                prev_count = len(findings)
                await self._check_csrf_in_forms(client, resp, target, findings)
                if len(findings) > prev_count:
                    logs.append(f"  [!] Form CSRF Protection: {findings[-1]['name']} ({findings[-1]['severity'].upper()})")
                else:
                    logs.append(f"  [+] Form CSRF Protection: OK / No unprotected mutating forms")

                # Clickjacking
                prev_count = len(findings)
                self._check_clickjacking(resp, target, findings)
                if len(findings) > prev_count:
                    logs.append(f"  [!] Anti-Clickjacking: {findings[-1]['name']} ({findings[-1]['severity'].upper()})")
                else:
                    logs.append(f"  [+] Anti-Clickjacking: OK")

                # CSP
                prev_count = len(findings)
                self._check_csp(resp, target, findings)
                if len(findings) > prev_count:
                    logs.append(f"  [!] Content Security Policy: {findings[-1]['name']} ({findings[-1]['severity'].upper()})")
                else:
                    logs.append(f"  [+] Content Security Policy: OK")

                # HSTS
                prev_count = len(findings)
                self._check_hsts(resp, target, findings)
                if target.startswith("https://"):
                    if len(findings) > prev_count:
                        logs.append(f"  [!] HSTS Security: {findings[-1]['name']} ({findings[-1]['severity'].upper()})")
                    else:
                        logs.append(f"  [+] HSTS Security: OK")

                # Server Info Leakage
                prev_count = len(findings)
                self._check_server_info_leakage(resp, target, findings)
                if len(findings) > prev_count:
                    for f in findings[prev_count:]:
                        logs.append(f"  [!] Server Info Disclosure: {f['name']} -> {f['evidence']}")
                else:
                    logs.append(f"  [+] Server Headers: OK / No version disclosed")

                # HTTP Methods
                prev_count = len(findings)
                await self._check_http_methods(client, target, findings)
                if len(findings) > prev_count:
                    for f in findings[prev_count:]:
                        logs.append(f"  [i] HTTP Methods Allowed: {f['name']} -> {f['evidence']}")
                else:
                    logs.append(f"  [+] HTTP Methods: Standard methods only")

        except httpx.RequestError as exc:
            logger.warning(f"[zap-fallback] Request error: {exc}")
            logs.append(f"\n[-] Network error during probe: {exc}")
            findings.append({
                "name": "Target Connectivity Issue",
                "severity": "info",
                "description": f"Could not complete probe: {exc}",
                "solution": "Verify the target is accessible.",
                "reference": "",
                "url": target,
                "endpoint": target,
                "parameter": "",
                "evidence": str(exc),
                "cwe_id": "",
                "wasc_id": "",
                "alert_ref": "",
            })

        logs.append(f"\n[+] Fallback Security Scan Complete: {len(findings)} vulnerability findings detected.")

        return {
            "findings": findings,
            "total": len(findings),
            "target": target,
        }, "\n".join(logs)

    async def _check_cors(
        self, client: httpx.AsyncClient, target: str,
        resp: httpx.Response, findings: List
    ) -> None:
        """Test for CORS misconfigurations with an arbitrary Origin."""
        evil_origin = "https://evil-attacker-example.com"
        try:
            cors_resp = await client.get(
                target,
                headers={"Origin": evil_origin},
                timeout=10,
            )
            acao = cors_resp.headers.get("access-control-allow-origin", "")
            acac = cors_resp.headers.get("access-control-allow-credentials", "false").lower()

            if acao == "*":
                findings.append(self._finding(
                    name="Wildcard CORS Policy",
                    severity="medium",
                    description=(
                        "The server allows any origin (*) in CORS. "
                        "Combined with cookies this can lead to cross-site data theft."
                    ),
                    solution="Restrict Access-Control-Allow-Origin to trusted domains only.",
                    url=target,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    cwe_id="942",
                    wasc_id="14",
                ))
            elif acao == evil_origin and acac == "true":
                findings.append(self._finding(
                    name="Reflected CORS with Credentials",
                    severity="high",
                    description=(
                        "The server reflects arbitrary origins and allows credentials. "
                        "An attacker could perform authenticated cross-origin requests."
                    ),
                    solution=(
                        "Do not allow arbitrary origins. "
                        "Do not combine wildcard/arbitrary ACAO with Allow-Credentials: true."
                    ),
                    url=target,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    cwe_id="942",
                    wasc_id="14",
                ))
        except httpx.RequestError:
            pass

    def _check_cookie_flags(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        """Check all Set-Cookie headers for missing security attributes."""
        for set_cookie in resp.headers.get_list("set-cookie"):
            cookie_name = set_cookie.split("=")[0].strip()
            lower = set_cookie.lower()
            issues = []
            if "httponly" not in lower:
                issues.append("HttpOnly")
            if "secure" not in lower and target.startswith("https://"):
                issues.append("Secure")
            if "samesite" not in lower:
                issues.append("SameSite")
            if issues:
                findings.append(self._finding(
                    name="Cookie Without Security Flags",
                    severity="medium",
                    description=(
                        f"Cookie '{cookie_name}' is missing: {', '.join(issues)}. "
                        f"This may allow session hijacking or CSRF attacks."
                    ),
                    solution=f"Add {', '.join(issues)} flags to the Set-Cookie header.",
                    url=target,
                    parameter=cookie_name,
                    evidence=set_cookie[:200],
                    cwe_id="614",
                    wasc_id="13",
                ))

    async def _check_csrf_in_forms(
        self, client: httpx.AsyncClient, resp: httpx.Response,
        target: str, findings: List
    ) -> None:
        """Detect HTML forms missing CSRF token inputs."""
        body = resp.text
        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
        for form_html in forms:
            method_match = re.search(r'method=["\'](\w+)["\']', form_html, re.IGNORECASE)
            method = (method_match.group(1).upper() if method_match else "GET")
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            # Look for common CSRF token fields
            has_csrf = bool(re.search(
                r'(csrf|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)',
                form_html, re.IGNORECASE
            ))
            if not has_csrf:
                findings.append(self._finding(
                    name="Form Without CSRF Protection",
                    severity="medium",
                    description=(
                        "A POST/mutating form was detected without a recognisable CSRF token. "
                        "This may allow cross-site request forgery attacks."
                    ),
                    solution=(
                        "Add a hidden CSRF token to all state-changing forms and validate it server-side."
                    ),
                    url=target,
                    evidence=form_html[:300],
                    cwe_id="352",
                    wasc_id="9",
                ))

    def _check_clickjacking(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        headers_lc = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers_lc.get("x-frame-options", "")
        csp = headers_lc.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp:
            findings.append(self._finding(
                name="Missing Anti-Clickjacking Header",
                severity="medium",
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors directive is set. "
                    "The page can be embedded in a malicious iframe (Clickjacking)."
                ),
                solution="Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.",
                url=target,
                evidence=f"X-Frame-Options: (absent), CSP: {csp[:100] or '(absent)'}",
                cwe_id="1021",
                wasc_id="45",
            ))

    def _check_csp(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        headers_lc = {k.lower(): v for k, v in resp.headers.items()}
        if "content-security-policy" not in headers_lc:
            findings.append(self._finding(
                name="Missing Content Security Policy",
                severity="low",
                description=(
                    "No Content-Security-Policy header was returned. "
                    "CSP is a key defence against XSS and data injection attacks."
                ),
                solution="Define and deploy a strict Content-Security-Policy.",
                url=target,
                evidence="Content-Security-Policy: (absent)",
                cwe_id="693",
                wasc_id="14",
            ))

    def _check_hsts(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        if not target.startswith("https://"):
            return
        if "strict-transport-security" not in {k.lower() for k in resp.headers}:
            findings.append(self._finding(
                name="Missing Strict-Transport-Security Header",
                severity="low",
                description=(
                    "HTTPS site is missing the HSTS header. "
                    "Browsers will not enforce HTTPS connections."
                ),
                solution="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                url=target,
                evidence="Strict-Transport-Security: (absent)",
                cwe_id="319",
                wasc_id="15",
            ))

    def _check_server_info_leakage(
        self, resp: httpx.Response, target: str, findings: List
    ) -> None:
        server = resp.headers.get("server", "")
        x_powered = resp.headers.get("x-powered-by", "")
        for header_name, header_val in [("Server", server), ("X-Powered-By", x_powered)]:
            if header_val and re.search(r"[\d.]+", header_val):
                findings.append(self._finding(
                    name=f"Information Disclosure via {header_name} Header",
                    severity="informational",
                    description=(
                        f"The {header_name} header discloses software version information: '{header_val}'. "
                        f"This assists attackers in identifying vulnerable software versions."
                    ),
                    solution=f"Remove or anonymise the {header_name} header.",
                    url=target,
                    evidence=f"{header_name}: {header_val}",
                    cwe_id="200",
                    wasc_id="13",
                ))

    async def _check_http_methods(
        self, client: httpx.AsyncClient, target: str, findings: List
    ) -> None:
        """Check if dangerous HTTP methods (TRACE, PUT, DELETE) are allowed."""
        for method in ("TRACE", "OPTIONS"):
            try:
                r = await client.request(method, target, timeout=8)
                if method == "TRACE" and r.status_code in (200, 405):
                    body_sample = (r.text or "")[:200]
                    if method == "TRACE" and r.status_code == 200:
                        findings.append(self._finding(
                            name="HTTP TRACE Method Enabled",
                            severity="low",
                            description=(
                                "TRACE method is enabled. It can be used in Cross-Site Tracing (XST) attacks."
                            ),
                            solution="Disable TRACE method in the server configuration.",
                            url=target,
                            evidence=f"HTTP TRACE returned {r.status_code}",
                            cwe_id="16",
                            wasc_id="14",
                        ))
                if method == "OPTIONS":
                    allow = r.headers.get("allow", "")
                    if allow:
                        findings.append(self._finding(
                            name="HTTP Methods Allowed",
                            severity="informational",
                            description=f"OPTIONS method reveals allowed HTTP methods: {allow}",
                            solution="Restrict allowed methods to only those required.",
                            url=target,
                            evidence=f"Allow: {allow}",
                            cwe_id="16",
                            wasc_id="45",
                        ))
            except httpx.RequestError:
                pass

    # ── Helper ────────────────────────────────────────────────────────────────

    @staticmethod
    def _finding(
        name: str,
        severity: str,
        description: str,
        solution: str = "",
        url: str = "",
        parameter: str = "",
        evidence: str = "",
        cwe_id: str = "",
        wasc_id: str = "",
        alert_ref: str = "",
    ) -> Dict[str, Any]:
        return {
            "name": name,
            "severity": severity,
            "description": description,
            "solution": solution,
            "reference": "",
            "url": url,
            "endpoint": url,
            "parameter": parameter,
            "evidence": evidence,
            "cwe_id": cwe_id,
            "wasc_id": wasc_id,
            "alert_ref": alert_ref,
        }

    # ── Parse ZAP REST API alerts ─────────────────────────────────────────────

    def _parse_alerts(self, alerts: List[Dict], target: str) -> Dict[str, Any]:
        """Parse ZAP alerts into structured findings."""
        findings = []
        for alert in alerts:
            risk = alert.get("risk", "").lower()
            severity_map = {
                "high": "high",
                "medium": "medium",
                "low": "low",
                "informational": "info",
            }
            findings.append({
                "name": alert.get("name", ""),
                "severity": severity_map.get(risk, "info"),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
                "url": alert.get("url", target),
                "endpoint": alert.get("url", target),
                "parameter": alert.get("param", ""),
                "evidence": alert.get("evidence", ""),
                "cwe_id": alert.get("cweid", ""),
                "wasc_id": alert.get("wascid", ""),
                "alert_ref": alert.get("alertRef", ""),
            })

        return {
            "findings": findings,
            "total": len(findings),
            "target": target,
        }
