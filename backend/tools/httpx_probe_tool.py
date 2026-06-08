"""HttpxProbeTool — HTTP probing and service discovery using ProjectDiscovery httpx.

Probes a list of hosts/URLs for live HTTP services, collects status codes,
titles, content-length, technologies, and TLS info. When the PD httpx binary
is not available (or the installed httpx is the Python CLI version), falls back
to a Python-based probe using the httpx library directly.
"""
from __future__ import annotations

import json
import shutil
from typing import Any, Dict, List, Optional, Tuple

import httpx as _httpx
from loguru import logger

from tools.base_tool import BaseTool


class HttpxProbeTool(BaseTool):
    """ProjectDiscovery httpx — bulk HTTP probing."""

    name = "httpx_probe"
    docker_image = None

    # The PD httpx binary name — distinct from Python's httpx CLI
    _PD_BINARY = "httpx"

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        return [
            self._PD_BINARY,
            "-u", target,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-content-length",
            "-tech-detect",
            "-follow-redirects",
            "-timeout", "10",
            "-no-color",
        ]

    def _binary_is_pd_httpx(self) -> bool:
        """Return True only when the installed httpx is ProjectDiscovery's."""
        path = shutil.which(self._PD_BINARY)
        if not path:
            return False
        # PD httpx lives in go/bin; Python httpx is in Scripts/
        return "go" in path.lower() or "projectdiscovery" in path.lower()

    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> "ToolResult":
        """Override run to force Python fallback when PD httpx is not present."""
        from datetime import datetime
        from app.models.scan import ToolResult, ToolStatus

        options = options or {}
        result = ToolResult(
            tool_name=self.name,
            status=ToolStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        try:
            if self._binary_is_pd_httpx():
                stdout, stderr, exit_code = await self._run_subprocess(target, options)
                result.raw_output = stdout[:50000]
                result.exit_code = exit_code
                result.parsed_data = self.parse_output(stdout, stderr, target)
                result.status = ToolStatus.COMPLETED
            else:
                logger.warning(
                    "[httpx_probe] ProjectDiscovery httpx not found. "
                    "Running Python HTTP probe fallback."
                )
                stdout, stderr, exit_code = self.fallback_run(target, options)
                result.raw_output = stdout[:50000]
                result.exit_code = exit_code
                result.parsed_data = self.parse_output(stdout, stderr, target)
                result.status = ToolStatus.COMPLETED
        except Exception as exc:
            result.status = ToolStatus.FAILED
            result.error = str(exc)
            logger.error(f"[httpx_probe] failed: {exc}")

        from datetime import datetime
        result.completed_at = datetime.utcnow()
        if result.started_at:
            result.duration_seconds = (
                result.completed_at - result.started_at
            ).total_seconds()
        return result

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Probe the target URL using the Python httpx library."""
        logger.info(f"[httpx_probe] Python HTTP probe fallback on {target}")
        results = []

        urls = options.get("urls", [target]) if isinstance(
            options.get("urls"), list
        ) else [target]

        import ssl, re
        for url in urls:
            try:
                with _httpx.Client(
                    timeout=10, follow_redirects=True, verify=False
                ) as client:
                    resp = client.get(url)

                    # Detect title
                    title_match = re.search(
                        r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE
                    )
                    title = title_match.group(1).strip() if title_match else ""

                    # Detect TLS
                    tls_info = {}
                    if url.startswith("https://"):
                        tls_info = {"tls": True}

                    # Detect tech from headers
                    techs = []
                    server = resp.headers.get("server", "")
                    powered_by = resp.headers.get("x-powered-by", "")
                    if server:
                        techs.append(server)
                    if powered_by:
                        techs.append(powered_by)

                    results.append({
                        "url": str(resp.url),
                        "input": url,
                        "status_code": resp.status_code,
                        "title": title,
                        "content_length": len(resp.content),
                        "content_type": resp.headers.get("content-type", ""),
                        "server": server,
                        "technologies": techs,
                        "tls": tls_info,
                        "final_url": str(resp.url),
                        "redirect_chain": [str(r.url) for r in resp.history],
                    })
            except _httpx.RequestError as exc:
                logger.debug(f"[httpx_probe-fallback] {url}: {exc}")
                results.append({
                    "url": url,
                    "input": url,
                    "status_code": -1,
                    "error": str(exc),
                })

        stdout = "\n".join(json.dumps(r) for r in results)
        return stdout, "", 0

    # ── Parse output ──────────────────────────────────────────────────────────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        probes = []
        live_urls = []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                sc = data.get("status_code", -1)
                probe = {
                    "url": data.get("url", data.get("input", "")),
                    "status_code": sc,
                    "title": data.get("title", ""),
                    "content_length": data.get("content_length", 0),
                    "content_type": data.get("content_type", ""),
                    "server": data.get("server", data.get("webserver", "")),
                    "technologies": data.get("technologies", data.get("tech", [])),
                    "tls": data.get("tls", {}),
                    "final_url": data.get("final_url", data.get("url", "")),
                    "redirect_chain": data.get("redirect_chain", []),
                    "error": data.get("error", ""),
                }
                probes.append(probe)
                if sc != -1 and not data.get("error"):
                    live_urls.append(probe["url"])
            except json.JSONDecodeError:
                continue

        return {
            "target": target,
            "probes": probes,
            "live_urls": live_urls,
            "total": len(probes),
            "live_count": len(live_urls),
        }
