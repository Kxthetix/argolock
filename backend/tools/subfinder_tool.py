"""Subfinder tool — subdomain enumeration."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool


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

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        subdomains = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                subdomains.append({
                    "subdomain": data.get("host", line),
                    "source": data.get("source", "subfinder"),
                    "ip": data.get("ip", ""),
                })
            except json.JSONDecodeError:
                # Plain text output fallback
                if line:
                    subdomains.append({"subdomain": line, "source": "subfinder"})

        return {
            "subdomains": subdomains,
            "total": len(subdomains),
            "target": target,
        }
