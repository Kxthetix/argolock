"""Subfinder tool — subdomain enumeration.

When the subfinder binary is not available, falls back to querying multiple
passive DNS sources directly in Python:
  1. crt.sh (Certificate Transparency logs)
  2. URLScan.io (web scanning archive)
  3. AlienVault OTX (threat intelligence passive DNS)
  4. RapidDNS (aggregated DNS records)
  5. DNS brute-force of common prefixes via system resolver

These sources complement the Amass fallback (which uses crt.sh + HackerTarget)
to maximise subdomain coverage.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool

# Common subdomain prefixes for brute-force resolution
_COMMON_PREFIXES = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "blog", "shop", "dev", "staging", "api", "admin", "portal", "vpn", "m",
    "app", "test", "owa", "server", "cloud", "git", "mx", "remote", "ww2",
    "cpanel", "whm", "autodiscover", "autoconfig", "sip", "dns", "dns1",
    "dns2", "ns3", "ns4", "imap", "pop3", "email", "secure", "beta",
    "cdn", "direct", "forum", "img", "images", "media", "static", "files",
    "download", "docs", "support", "help", "status", "monitor", "dashboard",
    "login", "sso", "auth", "go", "redirect", "relay", "proxy", "gateway",
    "jenkins", "ci", "jira", "wiki", "confluence", "gitlab", "bitbucket",
    "stg", "uat", "sandbox", "demo", "internal", "intranet", "corp",
]


class SubfinderTool(BaseTool):
    name = "subfinder"
    docker_image = settings.subfinder_docker_image

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        return [
            "subfinder",
            "-d", target,
            "-oJ",           # JSON output (JSONL per line)
            "-silent",
            "-timeout", "10",    # 10s per DNS/HTTP query per source
            "-max-time", "2",    # Max 2 minutes total enumeration time
            "-duc",              # Disable update check for speed
        ]

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(
        self, target: str, options: Dict[str, Any]
    ) -> Tuple[str, str, int]:
        """Query multiple passive DNS sources when the subfinder binary is missing."""
        logger.info(f"[subfinder] Running Python passive-DNS fallback for {target}")

        async def _fetch() -> str:
            subdomains: Dict[str, str] = {}  # name -> source

            async with httpx.AsyncClient(
                timeout=20, follow_redirects=True
            ) as client:

                # ── 1. crt.sh (Certificate Transparency) ─────────────────
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
                                if (
                                    name.endswith(f".{target}") or name == target
                                ) and name not in subdomains:
                                    subdomains[name] = "crt.sh"
                    logger.debug(
                        f"[subfinder-fallback] crt.sh yielded "
                        f"{sum(1 for s in subdomains.values() if s == 'crt.sh')} subs"
                    )
                except Exception as exc:
                    logger.debug(f"[subfinder-fallback] crt.sh error: {exc}")

                # ── 2. URLScan.io ─────────────────────────────────────────
                try:
                    r = await client.get(
                        f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=100",
                    )
                    if r.status_code == 200:
                        for result in r.json().get("results", []):
                            page = result.get("page", {})
                            domain = page.get("domain", "").strip()
                            if (
                                domain
                                and (domain.endswith(f".{target}") or domain == target)
                                and domain not in subdomains
                            ):
                                subdomains[domain] = "urlscan.io"
                except Exception as exc:
                    logger.debug(f"[subfinder-fallback] urlscan.io error: {exc}")

                # ── 3. AlienVault OTX ─────────────────────────────────────
                try:
                    r = await client.get(
                        f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
                    )
                    if r.status_code == 200:
                        for record in r.json().get("passive_dns", []):
                            hostname = record.get("hostname", "").strip()
                            if (
                                hostname
                                and (hostname.endswith(f".{target}") or hostname == target)
                                and hostname not in subdomains
                            ):
                                subdomains[hostname] = "alienvault"
                except Exception as exc:
                    logger.debug(f"[subfinder-fallback] alienvault error: {exc}")

                # ── 4. RapidDNS ───────────────────────────────────────────
                try:
                    r = await client.get(
                        f"https://rapiddns.io/subdomain/{target}?full=1",
                        headers={"Accept": "text/html"},
                    )
                    if r.status_code == 200:
                        # Extract subdomains from HTML table cells
                        pattern = re.compile(
                            r"([a-zA-Z0-9._-]+\." + re.escape(target) + r")"
                        )
                        for match in pattern.finditer(r.text):
                            name = match.group(1).strip()
                            if name not in subdomains:
                                subdomains[name] = "rapiddns"
                except Exception as exc:
                    logger.debug(f"[subfinder-fallback] rapiddns error: {exc}")

            # ── 5. DNS brute-force of common prefixes ─────────────────────
            resolved = 0
            for prefix in _COMMON_PREFIXES:
                fqdn = f"{prefix}.{target}"
                if fqdn in subdomains:
                    continue
                try:
                    socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
                    subdomains[fqdn] = "dns-bruteforce"
                    resolved += 1
                except (socket.gaierror, OSError):
                    pass
            if resolved:
                logger.debug(
                    f"[subfinder-fallback] DNS brute-force resolved {resolved} names"
                )

            # Build JSONL output (matches subfinder -oJ format)
            lines = []
            for name, source in subdomains.items():
                lines.append(json.dumps({
                    "host": name,
                    "source": source,
                    "ip": "",
                }))

            logger.info(
                f"[subfinder-fallback] Total unique subdomains found: {len(subdomains)}"
            )
            return "\n".join(lines)

        # Run the async fetch within the synchronous Celery worker context
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    fut = pool.submit(asyncio.run, _fetch())
                    stdout = fut.result(timeout=60)
            else:
                stdout = loop.run_until_complete(_fetch())
        except Exception as exc:
            logger.warning(f"[subfinder-fallback] fetch error: {exc}")
            stdout = ""

        return stdout, "", 0

    # ── Parse output ──────────────────────────────────────────────────────────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        subdomains = []
        seen: set = set()

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", line).strip()
                if host and host not in seen:
                    seen.add(host)
                    subdomains.append({
                        "subdomain": host,
                        "source": data.get("source", "subfinder"),
                        "ip": data.get("ip", ""),
                    })
            except json.JSONDecodeError:
                # Plain text output fallback
                if line and line not in seen:
                    seen.add(line)
                    subdomains.append({
                        "subdomain": line,
                        "source": "subfinder",
                        "ip": "",
                    })

        return {
            "subdomains": subdomains,
            "total": len(subdomains),
            "target": target,
        }
