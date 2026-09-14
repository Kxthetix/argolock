"""Nuclei Tool Adapter for Template-Driven Non-Destructive Vulnerability Validation."""
from __future__ import annotations

import json
import re
import shutil
from typing import Any, Dict, List, Optional
from tools.adapters.base_adapter import ToolAdapter
from tools.nuclei_tool import NucleiTool


class NucleiAdapter(ToolAdapter):
    tool_id = "nuclei"
    name = "Nuclei Template Engine"
    category = "vulnerability"
    supported_levels = ["level_0", "level_1", "level_2"]

    def __init__(self):
        super().__init__()
        self._underlying = NucleiTool()
        self.templates_version = "v10.0.0"

    def check_installation(self) -> bool:
        return shutil.which("nuclei") is not None

    def get_version(self) -> str:
        ret, stdout, _ = self._run_cmd_safe(["nuclei", "-version"], timeout=5)
        if ret == 0 and stdout:
            match = re.search(r"Nuclei Engine Version: ([\w\.-]+)", stdout)
            if match:
                return match.group(1)
        return "embedded-fallback-v1.6"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "template_validation": True,
            "cve_matching": True,
            "cwe_matching": True,
            "rate_limiting": True,
            "timeout_controls": True,
            "request_response_evidence": True,
            "templates_version": self.templates_version,
        }

    def build_test(self, target: str, context: Dict[str, Any]) -> List[str]:
        template_id = context.get("template_id")
        cmd = ["nuclei", "-u", target, "-silent", "-jsonl", "-timeout", "10", "-rate-limit", "50"]
        if template_id:
            cmd.extend(["-id", template_id])
        return cmd

    async def execute_validation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.execution_count += 1
        finding_id = context.get("finding_id", "manual")
        asset_id = context.get("asset_id", target)
        cve = context.get("cve")

        options: Dict[str, Any] = {"severity": ["critical", "high", "medium"]}
        if context.get("template_id"):
            options["tags"] = [context.get("template_id")]

        tool_res = await self._underlying.run(target, options)
        if tool_res.status.value == "completed":
            self.success_count += 1

        raw_output = tool_res.raw_output or ""
        evidence_list = []

        parsed_findings = tool_res.parsed_data.get("findings", []) if tool_res.parsed_data else []
        matched_finding = None

        # Check for specific CVE or matching template
        for f in parsed_findings:
            if cve and cve.lower() in str(f).lower():
                matched_finding = f
                break
            if not cve:
                matched_finding = f
                break

        if matched_finding:
            status = "confirmed"
            confidence = 0.95
            evidence_list.append(self.collect_evidence(json.dumps(matched_finding), context))
        elif parsed_findings:
            status = "validated"
            confidence = 0.85
            evidence_list.append(self.collect_evidence(json.dumps(parsed_findings[0]), context))
        else:
            status = "not_exploitable"
            confidence = 0.30
            evidence_list.append({
                "type": "scanner_output",
                "sample": "Nuclei validation template did not trigger condition.",
                "target": target
            })

        return self.normalize_result(
            finding_id=finding_id,
            asset_id=asset_id,
            status=status,
            confidence=confidence,
            evidence=evidence_list,
            cve=cve or (matched_finding.get("cve", [""])[0] if matched_finding and matched_finding.get("cve") else ""),
            cwe=context.get("cwe") or "CWE-200",
            severity=matched_finding.get("severity", context.get("severity", "medium")) if matched_finding else context.get("severity", "medium"),
            execution_status="completed" if tool_res.status.value == "completed" else "failed",
        )

    def parse_result(self, raw_output: str) -> List[Dict[str, Any]]:
        return self._underlying.parse_output(raw_output, "", "")

    def collect_evidence(self, raw_output: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "http_request_response",
            "evidence_body": raw_output[:3000],
            "target": context.get("target", ""),
            "tool": "nuclei",
            "template_version": self.templates_version,
        }
