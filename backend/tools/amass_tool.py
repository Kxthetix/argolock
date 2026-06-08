"""Amass tool — OSINT-based subdomain enumeration.

Amass performs deep passive enumeration using OSINT sources (crt.sh, ASN data,
DNS brute-forcing, etc.). When the binary is missing, falls back to querying
crt.sh and hackertarget APIs directly in Python for real passive DNS data.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger

from tools.base_tool import BaseTool


class AmassTool(BaseTool):
    name = "amass"
    docker_image = None

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        timeout_min = options.get("timeout_minutes", 2)
        return [
            "amass", "enum",
            "-d", target,
            "-silent",
            "-json",        # JSONL output per subdomain
            "-timeout", str(timeout_min),
            "-passive",     # Passive-only (no active DNS brute-force)
        ]

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Query crt.sh and HackerTarget for real passive DNS data."""
        import asyncio
        logger.info(f"[amass] Running Python passive DNS fallback for {target}")

        async def _fetch():
            subdomains: Dict[str, set] = {}

            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                # ── crt.sh ────────────────────────────────────────────────────
                try:
                    r = await client.get(
                        f"https://crt.sh/?q=%.{target}&output=json",
                        headers={"Accept": "application/json"},
                    )
                    if r.status_code == 200:
                        for entry in r.json():
                            names = entry.get("name_value", "")
                            for name in names.splitlines():
                                name = name.strip().lstrip("*.")
                                if name.endswith(f".{target}") or name == target:
                                    subdomains.setdefault(name, set()).add("crt.sh")
                except Exception as exc:
                    logger.debug(f"[amass-fallback] crt.sh error: {exc}")

                # ── HackerTarget ──────────────────────────────────────────────
                try:
                    r = await client.get(
                        f"https://api.hackertarget.com/hostsearch/?q={target}"
                    )
                    if r.status_code == 200 and "error" not in r.text.lower():
                        for line in r.text.strip().splitlines():
                            parts = line.split(",")
                            if parts:
                                name = parts[0].strip()
                                if name.endswith(f".{target}") or name == target:
                                    subdomains.setdefault(name, set()).add("hackertarget")
                except Exception as exc:
                    logger.debug(f"[amass-fallback] hackertarget error: {exc}")

            # Format as Amass JSON lines
            lines = []
            for name, sources in subdomains.items():
                lines.append(json.dumps({
                    "name": name,
                    "domain": target,
                    "addresses": [],
                    "tag": "cert",
                    "sources": list(sources),
                }))
            return "\n".join(lines)

        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    fut = pool.submit(asyncio.run, _fetch())
                    stdout = fut.result(timeout=30)
            else:
                stdout = loop.run_until_complete(_fetch())
        except Exception as exc:
            logger.warning(f"[amass-fallback] fetch error: {exc}")
            stdout = ""

        return stdout, "", 0

    # ── Parse output ──────────────────────────────────────────────────────────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        subdomains = []
        seen: set = set()

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "").strip()
                if name and name not in seen:
                    seen.add(name)
                    addresses = data.get("addresses", [])
                    ips = [a.get("ip", "") for a in addresses if isinstance(a, dict)]
                    subdomains.append({
                        "subdomain": name,
                        "source": "amass",
                        "sources": data.get("sources", []),
                        "ip": ips[0] if ips else "",
                        "tag": data.get("tag", ""),
                    })
            except json.JSONDecodeError:
                # Plain text line
                name = line.strip()
                if name and name not in seen:
                    seen.add(name)
                    subdomains.append({"subdomain": name, "source": "amass", "ip": ""})

        return {
            "subdomains": subdomains,
            "total": len(subdomains),
            "target": target,
        }
