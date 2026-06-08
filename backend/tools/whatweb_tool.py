"""WhatWeb tool — web technology fingerprinting.

When the ``whatweb`` binary is not installed, this module performs a real
HTTP-based technology fingerprinting probe using Python's httpx library and
returns results in the exact same schema WhatWeb would produce.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger

from tools.base_tool import BaseTool


# ── Technology fingerprinting patterns ───────────────────────────────────────
# Each entry: (plugin_name, header_key_or_None, body_regex_or_None, cookie_key_or_None)
_TECH_PATTERNS: List[Tuple[str, Optional[str], Optional[str], Optional[str]]] = [
    # Server-header based
    ("Apache",          None, None, None),   # handled via Server header
    ("Nginx",           None, None, None),   # handled via Server header
    ("Microsoft-IIS",   None, None, None),   # handled via Server header
    ("Cloudflare",      "cf-ray", None, None),
    ("Cloudflare",      "server", r"cloudflare", None),
    # X-Powered-By
    ("PHP",             "x-powered-by", r"php/([\d.]+)", None),
    ("ASP.NET",         "x-powered-by", r"ASP\.NET", None),
    ("X-Powered-By",    "x-powered-by", r"(.*)", None),
    # Cookies
    ("PHP",             None, None, "PHPSESSID"),
    ("Java/Servlet",    None, None, "JSESSIONID"),
    ("Django",          None, None, "csrftoken"),
    ("Rails",           None, None, "_session_id"),
    ("Laravel",         None, None, "laravel_session"),
    # HTML body
    ("WordPress",       None, r"/wp-content/", None),
    ("WordPress",       None, r"/wp-includes/", None),
    ("Joomla",          None, r'content="joomla', None),
    ("Drupal",          None, r'Drupal\.settings', None),
    ("React",           None, r"__reactFiber|__reactEvents|react-root", None),
    ("Vue.js",          None, r"__vue__|vue-app", None),
    ("Angular",         None, r"ng-version=|angular\.js", None),
    ("jQuery",          None, r"jquery[\.-]([\d.]+)(\.min)?\.js", None),
    ("Bootstrap",       None, r"bootstrap[\.-]([\d.]+)(\.min)?\.css", None),
    ("Next.js",         None, r"/_next/static/", None),
    ("Nuxt.js",         None, r"/_nuxt/", None),
    ("Gatsby",          None, r"/gatsby-", None),
    ("Shopify",         None, r"cdn\.shopify\.com", None),
    ("Wix",             None, r"static\.wixstatic\.com", None),
    ("Google Analytics",None, r"UA-\d{4,}-\d+|G-[A-Z0-9]+|gtag\(|ga\.js", None),
    ("Google Tag Manager",None,r"googletagmanager\.com/gtm\.js", None),
    ("Generator",       None, r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', None),
]

_VERSION_HEADERS = {
    "x-powered-by": r"(?:php|asp\.net)[/\s]([\d.]+)",
    "server": r"(?:nginx|apache|iis)[/\s]([\d.]+)",
}


class WhatWebTool(BaseTool):
    name = "whatweb"
    docker_image = None  # No docker image — subprocess only

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        return [
            "whatweb",
            "--log-json=-",   # JSON to stdout
            "--no-errors",
            "-a", "3",        # Aggression level 3
            target,
        ]

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Probe target via HTTP and fingerprint technologies from real responses."""
        logger.info(f"[whatweb] Running Python HTTP fingerprinting probe on {target}")
        plugins: Dict[str, Dict] = {}

        try:
            with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
                resp = client.get(target)
            self._probe_response(resp, plugins)
        except httpx.RequestError as exc:
            logger.warning(f"[whatweb] HTTP probe failed: {exc}")
            # Return completed with empty data rather than crash
            output = json.dumps([{"target": target, "plugins": {}}])
            return output, "", 0

        result = [{"target": target, "plugins": plugins}]
        stdout = json.dumps(result)
        return stdout, "", 0

    def _probe_response(self, resp: httpx.Response, plugins: Dict) -> None:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:100_000]  # first 100 KB

        # ── Server header ──────────────────────────────────────────────────────
        server = headers.get("server", "")
        if server:
            plugins["HTTPServer"] = {"string": [server]}
            # Extract server type
            for srv in ("Nginx", "Apache", "Microsoft-IIS", "cloudflare", "LiteSpeed"):
                if srv.lower() in server.lower():
                    version = re.search(r"[\d.]+", server)
                    plugins[srv] = {"version": [version.group()] if version else []}

        # ── X-Powered-By ──────────────────────────────────────────────────────
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            plugins["X-Powered-By"] = {"string": [powered_by]}
            ver = re.search(r"([\d.]+)", powered_by)
            if "php" in powered_by.lower():
                plugins["PHP"] = {"version": [ver.group(1)] if ver else []}
            if "asp.net" in powered_by.lower():
                plugins["ASP.NET"] = {"version": [ver.group(1)] if ver else []}

        # ── Security headers ──────────────────────────────────────────────────
        for h in ("strict-transport-security", "content-security-policy",
                  "x-frame-options", "x-content-type-options",
                  "x-xss-protection", "referrer-policy"):
            if h in headers:
                clean_name = h.replace("-", " ").title().replace(" ", "-")
                plugins[clean_name] = {"string": [headers[h]]}

        # ── Cookies ───────────────────────────────────────────────────────────
        cookie_header = headers.get("set-cookie", "")
        if cookie_header:
            for _pname, _hkey, _regex, cookie_key in _TECH_PATTERNS:
                if cookie_key and cookie_key.lower() in cookie_header.lower():
                    plugins[_pname] = plugins.get(_pname, {})

        # ── HTML body patterns ────────────────────────────────────────────────
        for tech_name, header_key, body_regex, _cookie_key in _TECH_PATTERNS:
            if body_regex and body:
                m = re.search(body_regex, body, re.IGNORECASE)
                if m:
                    entry = plugins.get(tech_name, {})
                    if m.lastindex and m.lastindex >= 1:
                        versions = entry.get("version", [])
                        v = m.group(1)
                        if v and v not in versions:
                            versions.append(v)
                        entry["version"] = versions
                    plugins[tech_name] = entry

        # ── Cloudflare CDN detection ──────────────────────────────────────────
        if "cf-ray" in headers:
            plugins["Cloudflare"] = {"string": [headers.get("cf-ray", "")]}

        # ── Meta generator ────────────────────────────────────────────────────
        gen_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body, re.IGNORECASE
        )
        if gen_match:
            plugins["Generator"] = {"string": [gen_match.group(1)]}

        # ── HTTP Status ───────────────────────────────────────────────────────
        plugins["Status"] = {"string": [str(resp.status_code)]}
        plugins["Title"] = self._extract_title(body)

    @staticmethod
    def _extract_title(body: str) -> Dict:
        m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        return {"string": [m.group(1).strip()]} if m else {}

    # ── Parse output (handles both real WhatWeb JSON and fallback JSON) ───────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        technologies = []
        headers: Dict[str, Any] = {}
        server_info: Dict[str, Any] = {}

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    for item in data:
                        self._extract_item(item, technologies, headers, server_info)
                elif isinstance(data, dict):
                    self._extract_item(data, technologies, headers, server_info)
            except json.JSONDecodeError:
                continue

        return {
            "target": target,
            "technologies": technologies,
            "headers": headers,
            "server_info": server_info,
        }

    def _extract_item(self, item: dict, technologies: list, headers: dict, server_info: dict):
        plugins = item.get("plugins", {})
        for plugin_name, plugin_data in plugins.items():
            tech = {"name": plugin_name, "version": [], "detail": []}
            if isinstance(plugin_data, dict):
                tech["version"] = plugin_data.get("version", [])
                tech["detail"] = plugin_data.get("string", [])
            technologies.append(tech)

            if plugin_name == "HTTPServer":
                server_info["server"] = (
                    plugin_data.get("string", [""])[0]
                    if isinstance(plugin_data, dict) and plugin_data.get("string") else ""
                )
            if plugin_name == "X-Powered-By":
                server_info["powered_by"] = (
                    plugin_data.get("string", [])
                    if isinstance(plugin_data, dict) else []
                )
