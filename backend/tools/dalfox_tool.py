"""Dalfox tool — powerful XSS scanner by hahwul.

Dalfox performs parameter-based XSS detection with real payload injection.
When the binary is missing, falls back to a Python-based XSS probe that:
  1. Crawls the target page for form inputs and URL parameters
  2. Injects XSS reflection test payloads
  3. Checks responses for reflected unescaped payload content
All results come from real live network requests — no fake data.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger

from tools.base_tool import BaseTool


# Reflection-test payloads — simple strings we check appear unescaped in response
_REFLECTION_PROBES = [
    '<dalfox-xss-probe-1"\'/>',
    "dalfox-xss-probe-2<img>",
    "<script>dalfox_probe_3</script>",
]

# Minimal encoded forms to check if HTML encoding happens
_PAYLOAD_MAP = {
    '<dalfox-xss-probe-1"\'/>': [
        "dalfox-xss-probe-1",   # substring if reflected raw
        "&lt;dalfox-xss-probe-1",  # substring if HTML-encoded (SAFE)
    ],
    'dalfox-xss-probe-2<img>': ["dalfox-xss-probe-2<img>"],
    "<script>dalfox_probe_3</script>": ["dalfox_probe_3"],
}


class DalfoxTool(BaseTool):
    name = "dalfox"
    docker_image = None

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        return [
            "dalfox", "url",
            target,
            "--format", "json",
            "--no-color",
            "--timeout", "10",
            "--silence",
            "--skip-bav",       # Skip blind attack vectors (faster)
        ]

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Real Python XSS reflection probe."""
        logger.info(f"[dalfox] Running Python XSS reflection probe on {target}")

        import asyncio

        async def _scan():
            findings: List[Dict[str, Any]] = []

            async with httpx.AsyncClient(
                timeout=12, follow_redirects=True, verify=False
            ) as client:
                try:
                    base_resp = await client.get(target)
                except httpx.RequestError as exc:
                    logger.warning(f"[dalfox-fallback] Cannot reach target: {exc}")
                    return findings

                body = base_resp.text

                # ── Collect URL parameters from page links ─────────────────────
                param_urls = self._collect_param_urls(target, body, base_resp)

                # ── Collect form inputs ────────────────────────────────────────
                form_targets = self._collect_forms(target, body)

                # ── Probe URL parameters ───────────────────────────────────────
                for url, param in param_urls:
                    result = await self._probe_param(client, url, param, "GET")
                    if result:
                        findings.append(result)

                # ── Probe form inputs ──────────────────────────────────────────
                for form_url, inputs, method in form_targets:
                    result = await self._probe_form(client, form_url, inputs, method)
                    if result:
                        findings.extend(result)

                # ── Probe the target URL's own query params ────────────────────
                parsed = urllib.parse.urlparse(target)
                qs = urllib.parse.parse_qs(parsed.query)
                for param in qs:
                    result = await self._probe_param(client, target, param, "GET")
                    if result:
                        findings.append(result)

            return findings

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    fut = pool.submit(asyncio.run, _scan())
                    findings = fut.result(timeout=60)
            else:
                findings = loop.run_until_complete(_scan())
        except Exception as exc:
            logger.warning(f"[dalfox-fallback] scan error: {exc}")
            findings = []

        stdout = "\n".join(json.dumps(f) for f in findings)
        return stdout, "", 0

    def _collect_param_urls(
        self, base: str, body: str, resp: httpx.Response
    ) -> List[Tuple[str, str]]:
        """Find all internal URLs with query parameters."""
        results = []
        base_parsed = urllib.parse.urlparse(base)

        for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
            href = m.group(1)
            full = urllib.parse.urljoin(base, href)
            parsed = urllib.parse.urlparse(full)
            if parsed.netloc != base_parsed.netloc:
                continue
            qs = urllib.parse.parse_qs(parsed.query)
            for param in qs:
                results.append((full, param))

        return results[:20]  # cap at 20 to keep it fast

    def _collect_forms(
        self, base: str, body: str
    ) -> List[Tuple[str, List[str], str]]:
        """Extract form actions, input names, and methods."""
        results = []
        for form_match in re.finditer(
            r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE
        ):
            form_html = form_match.group(0)
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_m = re.search(r'method=["\'](\w+)["\']', form_html, re.IGNORECASE)
            action = urllib.parse.urljoin(base, action_m.group(1)) if action_m else base
            method = (method_m.group(1).upper() if method_m else "GET")
            inputs = re.findall(
                r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE
            )
            if inputs:
                results.append((action, inputs, method))
        return results[:10]

    async def _probe_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        method: str,
    ) -> Optional[Dict]:
        """Inject XSS probes into a single URL parameter."""
        for probe in _REFLECTION_PROBES:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [probe]
                new_qs = urllib.parse.urlencode(qs, doseq=True)
                probe_url = parsed._replace(query=new_qs).geturl()
                resp = await client.get(probe_url, timeout=8)
                reflection = self._check_reflection(probe, resp.text)
                if reflection:
                    return {
                        "type": "GET_PARAM",
                        "parameter": param,
                        "url": probe_url,
                        "endpoint": url,
                        "payload": probe,
                        "evidence": reflection,
                        "severity": "high",
                        "poc": probe_url,
                        "description": f"XSS reflected parameter '{param}' in GET request",
                    }
            except httpx.RequestError:
                pass
        return None

    async def _probe_form(
        self,
        client: httpx.AsyncClient,
        form_url: str,
        inputs: List[str],
        method: str,
    ) -> List[Dict]:
        found = []
        for inp in inputs:
            for probe in _REFLECTION_PROBES:
                try:
                    data = {i: "test" for i in inputs}
                    data[inp] = probe
                    if method == "POST":
                        resp = await client.post(form_url, data=data, timeout=8)
                    else:
                        resp = await client.get(form_url, params=data, timeout=8)
                    reflection = self._check_reflection(probe, resp.text)
                    if reflection:
                        found.append({
                            "type": f"FORM_{method}",
                            "parameter": inp,
                            "url": form_url,
                            "endpoint": form_url,
                            "payload": probe,
                            "evidence": reflection,
                            "severity": "high",
                            "poc": f"{method} {form_url} [{inp}={probe}]",
                            "description": f"XSS reflected input '{inp}' in {method} form",
                        })
                        break  # one finding per input is enough
                except httpx.RequestError:
                    pass
        return found

    @staticmethod
    def _check_reflection(probe: str, body: str) -> Optional[str]:
        """Return evidence string if probe is reflected unescaped in body."""
        checks = _PAYLOAD_MAP.get(probe, [probe])
        for check in checks[:1]:  # Only check first (unescaped form)
            idx = body.find(check)
            if idx != -1:
                # Make sure it's not HTML-encoded (that would be safe)
                snippet = body[max(0, idx - 20): idx + len(check) + 20]
                if "&lt;" not in snippet and "&gt;" not in snippet:
                    return snippet
        return None

    # ── Parse output (real Dalfox JSON + fallback JSON) ───────────────────────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        findings = []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)

                # Real Dalfox JSON format
                if "type" in data and "param" in data:
                    findings.append({
                        "type": data.get("type", ""),
                        "parameter": data.get("param", ""),
                        "url": data.get("evidence", {}).get("url", target),
                        "endpoint": target,
                        "payload": data.get("evidence", {}).get("payload", ""),
                        "severity": "high",
                        "poc": data.get("poc", ""),
                        "description": data.get("description", "XSS vulnerability found"),
                        "evidence": data.get("evidence", {}).get("response", ""),
                    })
                # Fallback / Python format
                elif "parameter" in data:
                    findings.append(data)
            except json.JSONDecodeError:
                # Plain text Dalfox output (non-JSON mode)
                if "[V]" in line or "[I]" in line:
                    findings.append({
                        "type": "reflected",
                        "url": target,
                        "endpoint": target,
                        "parameter": "",
                        "payload": "",
                        "severity": "high",
                        "poc": "",
                        "description": line.strip(),
                        "evidence": "",
                    })

        return {
            "target": target,
            "findings": findings,
            "total": len(findings),
        }
