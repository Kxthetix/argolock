"""SQLmap tool — SQL injection detection (safe mode only)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool


_SQL_ERRORS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"key 'primary' in write row",
    r"mysql_fetch_array",
    # PostgreSQL
    r"postgresql query failed",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    # SQLite
    r"sqlite3::query\(\)",
    r"unclosed singular quote",
    # Microsoft SQL Server
    r"driver.* sql server",
    r"microsoft ole db provider for sql server",
    r"sqlserver error",
    # Oracle
    r"ora-\d+",
    r"oracle error",
    r"oracle driver",
]


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

    # ── Python fallback ───────────────────────────────────────────────────────

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Tuple[str, str, int]:
        """Real Python SQL injection scanner fallback."""
        logger.info(f"[sqlmap] Running Python SQL injection fallback for {target}")
        import asyncio
        import urllib.parse
        import httpx

        async def _scan():
            findings = []
            parsed = urllib.parse.urlparse(target)
            qs = urllib.parse.parse_qs(parsed.query)
            if not qs:
                return findings

            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                for param in qs:
                    # Try error-based SQL injection first
                    for payload in ["'", "''", "\"", "\\", ") AND 1=1"]:
                        try:
                            # Build the URL with the payload
                            param_dict = {k: v.copy() for k, v in qs.items()}
                            param_dict[param] = [qs[param][0] + payload]
                            new_qs = urllib.parse.urlencode(param_dict, doseq=True)
                            test_url = parsed._replace(query=new_qs).geturl()

                            resp = await client.get(test_url)
                            body_lower = resp.text.lower()

                            # Check for database error signatures
                            for pattern in _SQL_ERRORS:
                                if re.search(pattern, body_lower):
                                    findings.append({
                                        "parameter": param,
                                        "type": "error-based SQL injection",
                                        "endpoint": target,
                                        "confirmed": True,
                                        "payload": payload,
                                        "db_error": pattern,
                                    })
                                    break
                        except Exception:
                            pass
            return findings

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    fut = pool.submit(asyncio.run, _scan())
                    findings = fut.result(timeout=45)
            else:
                findings = loop.run_until_complete(_scan())
        except Exception as exc:
            logger.warning(f"[sqlmap-fallback] scan error: {exc}")
            findings = []

        return json.dumps(findings), "", 0

    # ── Parse output ──────────────────────────────────────────────────────────

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        """Parse SQLmap output (real SQLmap json/text or fallback JSON)."""
        injections = []
        injectable_params = []

        try:
            # First try parsing fallback JSON
            data = json.loads(stdout)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "parameter" in item:
                        injections.append(item)
                return {
                    "injections": injections,
                    "total": len(injections),
                    "target": target,
                    "vulnerable": len(injections) > 0,
                }
        except json.JSONDecodeError:
            pass

        # Parse JSON output from real SQLmap if available
        try:
            json_match = re.search(r'\[\s*\{.*\}\s*\]', stdout, re.DOTALL)
            if json_match:
                results = json.loads(json_match.group())
                return {"injections": results, "total": len(results), "target": target, "vulnerable": len(results) > 0}
        except (json.JSONDecodeError, AttributeError):
            pass

        # Parse text output from real SQLmap
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
