"""Nmap Tool Adapter for Discovery and Service Validation."""
from __future__ import annotations

import re
import shutil
from typing import Any, Dict, List, Optional
from tools.adapters.base_adapter import ToolAdapter
from tools.nmap_tool import NmapTool


class NmapAdapter(ToolAdapter):
    tool_id = "nmap"
    name = "Nmap Network Scanner"
    category = "discovery"
    supported_levels = ["level_0", "level_1"]

    def __init__(self):
        super().__init__()
        self._underlying = NmapTool()

    def check_installation(self) -> bool:
        return shutil.which("nmap") is not None

    def get_version(self) -> str:
        ret, stdout, _ = self._run_cmd_safe(["nmap", "--version"], timeout=5)
        if ret == 0 and stdout:
            match = re.search(r"Nmap version ([\d\.]+)", stdout)
            if match:
                return match.group(1)
        return "unknown"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "service_detection": True,
            "os_detection": False,
            "banner_grabbing": True,
            "safe_nse_scripts": True,
            "supported_protocols": ["tcp", "udp"],
        }

    def build_test(self, target: str, context: Dict[str, Any]) -> List[str]:
        ports = context.get("ports", "80,443")
        return ["nmap", "-sT", "-sV", "-Pn", "--open", "-p", str(ports), target]

    async def execute_validation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.execution_count += 1
        finding_id = context.get("finding_id", "manual")
        asset_id = context.get("asset_id", target)
        ports = context.get("port") or context.get("ports", "80,443")

        tool_res = await self._underlying.run(target, {"ports": str(ports)})
        if tool_res.status.value == "completed":
            self.success_count += 1

        raw_output = tool_res.raw_output or ""
        evidence = self.collect_evidence(raw_output, context)
        
        # Check if service was detected
        service_found = False
        parsed_ports = tool_res.parsed_data.get("ports", []) if tool_res.parsed_data else []
        for p in parsed_ports:
            if p.get("state") == "open":
                service_found = True
                break

        status = "validated" if service_found else "not_exploitable"
        confidence = 0.90 if service_found else 0.40

        return self.normalize_result(
            finding_id=finding_id,
            asset_id=asset_id,
            status=status,
            confidence=confidence,
            evidence=[evidence],
            cve=context.get("cve"),
            severity=context.get("severity", "info"),
            execution_status="completed" if tool_res.status.value == "completed" else "failed",
        )

    def parse_result(self, raw_output: str) -> List[Dict[str, Any]]:
        return self._underlying.parse_output(raw_output, "", "")

    def collect_evidence(self, raw_output: str, context: Dict[str, Any]) -> Dict[str, Any]:
        sample = raw_output[:2000] if raw_output else "No scanner output"
        return {
            "type": "service_banner",
            "raw_snippet": sample,
            "target": context.get("target", ""),
            "port": context.get("port", ""),
        }
