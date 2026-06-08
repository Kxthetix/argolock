"""SQLmap tool — SQL injection detection (safe mode only)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool


class SQLmapTool(BaseTool):
    name = "sqlmap"
    docker_image = settings.sqlmap_docker_image

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        SQLmap in SAFE mode only:
        - level=1, risk=1 (minimal)
        - no data extraction
        - batch mode (no prompts)
        - JSON output
        """
        cmd = [
            "python3", "/sqlmap/sqlmap.py",
            "-u", target,
            "--batch",           # Non-interactive
            "--level", "1",      # Minimal test level
            "--risk", "1",       # Minimal risk (no heavy payloads)
            "--timeout", "30",
            "--retries", "1",
            "--output-dir", "/tmp/sqlmap_out",
            "--forms",           # Test HTML forms
            "--crawl", "1",      # Shallow crawl
            "--threads", "1",    # Single thread
            "--json-output",     # JSON output (SQLmap 1.7+)
        ]

        # Safe mode — never dump data
        if settings.safe_mode:
            cmd.extend([
                "--technique", "B",  # Boolean-based only (safest)
            ])
        else:
            cmd.extend([
                "--technique", "BEUST",  # All techniques
            ])

        return cmd

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        """Parse SQLmap output for injection findings."""
        injections = []
        injectable_params = []
        databases = []

        # Parse JSON output if available
        try:
            json_match = re.search(r'\[\s*\{.*\}\s*\]', stdout, re.DOTALL)
            if json_match:
                results = json.loads(json_match.group())
                return {"injections": results, "total": len(results)}
        except (json.JSONDecodeError, AttributeError):
            pass

        # Parse text output
        # Look for injection messages
        injectable_pattern = re.compile(
            r'Parameter: ([^\s]+)[^\n]*\n.*Type: ([^\n]+)', re.MULTILINE
        )
        for match in injectable_pattern.finditer(stdout):
            injections.append({
                "parameter": match.group(1),
                "type": match.group(2).strip(),
                "endpoint": target,
                "confirmed": True,
            })

        # Check if sqlmap found anything
        if "sqlmap identified the following injection point" in stdout:
            injectable_params = re.findall(r"Parameter: (\S+)", stdout)

        return {
            "injections": injections,
            "injectable_parameters": injectable_params,
            "total": len(injections),
            "target": target,
            "vulnerable": len(injections) > 0,
        }
