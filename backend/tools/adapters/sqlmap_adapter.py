"""SQLMap Tool Adapter for Non-Destructive SQL Injection Validation."""
from __future__ import annotations

import json
import shutil
from typing import Any, Dict, List, Optional
from tools.adapters.base_adapter import ToolAdapter
from tools.sqlmap_tool import SQLmapTool


class SQLMapAdapter(ToolAdapter):
    tool_id = "sqlmap"
    name = "SQLMap Injection Verifier"
    category = "web_api"
    supported_levels = ["level_1", "level_2"]

    def __init__(self):
        super().__init__()
        self._underlying = SQLmapTool()

    def check_installation(self) -> bool:
        return shutil.which("sqlmap") is not None or shutil.which("sqlmap.py") is not None

    def get_version(self) -> str:
        ret, stdout, _ = self._run_cmd_safe(["sqlmap", "--version"], timeout=5)
        if ret == 0 and stdout:
            return stdout.strip().split()[-1]
        return "embedded-fallback-v1.6"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "non_destructive_verification": True,
            "data_dump_disabled": True,  # Hard-enforced safety
            "boolean_blind_verification": True,
            "error_based_verification": True,
            "parameter_isolation": True,
        }

    def build_test(self, target: str, context: Dict[str, Any]) -> List[str]:
        # Always safe mode: level 1, risk 1, batch, no dump
        param = context.get("parameter")
        cmd = ["sqlmap", "-u", target, "--batch", "--level=1", "--risk=1", "--technique=B", "--timeout=15"]
        if param:
            cmd.extend(["-p", param])
        return cmd

    async def execute_validation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.execution_count += 1
        finding_id = context.get("finding_id", "manual")
        asset_id = context.get("asset_id", target)

        # Run underlying safe sqlmap scanner (uses python fallback probe if binary not present)
        tool_res = await self._underlying.run(target, {"parameter": context.get("parameter")})
        if tool_res.status.value == "completed":
            self.success_count += 1

        raw_output = tool_res.raw_output or ""
        evidence_list = []

        is_injectable = False
        parsed_injections = tool_res.parsed_data.get("injections", []) if tool_res.parsed_data else []
        if parsed_injections:
            is_injectable = True
            evidence_list.append(self.collect_evidence(json.dumps(parsed_injections), context))
        else:
            evidence_list.append({
                "type": "sql_syntax_check",
                "result": "No SQL syntax anomalies or differential responses observed under safe non-destructive probing.",
                "target": target
            })

        status = "confirmed" if is_injectable else "not_exploitable"
        confidence = 0.95 if is_injectable else 0.35

        return self.normalize_result(
            finding_id=finding_id,
            asset_id=asset_id,
            status=status,
            confidence=confidence,
            evidence=evidence_list,
            cve=context.get("cve"),
            cwe="CWE-89",
            severity="high" if is_injectable else "low",
            execution_status="completed" if tool_res.status.value == "completed" else "failed",
        )

    def parse_result(self, raw_output: str) -> List[Dict[str, Any]]:
        return self._underlying.parse_output(raw_output, "", "")

    def collect_evidence(self, raw_output: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "sql_injection_proof",
            "evidence": raw_output[:3000],
            "parameter": context.get("parameter", "url_query"),
            "technique": "Boolean/Syntax differential test (Non-destructive)",
        }
