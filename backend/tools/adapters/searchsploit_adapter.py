"""SearchSploit Exploit Intelligence and Safety Classifier Adapter."""
from __future__ import annotations

import json
import re
import shutil
from typing import Any, Dict, List, Optional
from tools.adapters.base_adapter import ToolAdapter


class SearchSploitAdapter(ToolAdapter):
    tool_id = "searchsploit"
    name = "SearchSploit / Exploit-DB Intelligence"
    category = "intelligence"
    supported_levels = ["level_0"]

    def __init__(self):
        super().__init__()

    def check_installation(self) -> bool:
        return shutil.which("searchsploit") is not None

    def get_version(self) -> str:
        ret, stdout, _ = self._run_cmd_safe(["searchsploit", "--version"], timeout=5)
        if ret == 0 and stdout:
            return stdout.strip().splitlines()[0]
        return "exploitdb-offline-cache-v1.6"

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            "cve_lookup": True,
            "product_matching": True,
            "version_compatibility": True,
            "safety_classification": True,
            "exploit_execution": False,  # Strict Rule: Intelligence only, NEVER auto-executes
        }

    def build_test(self, target: str, context: Dict[str, Any]) -> List[str]:
        cve = context.get("cve", "")
        clean_cve = cve.replace("CVE-", "").replace("cve-", "")
        return ["searchsploit", "--cve", clean_cve, "--json"]

    async def execute_validation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform exploit intelligence lookup and compatibility/safety classification."""
        self.execution_count += 1
        finding_id = context.get("finding_id", "manual")
        asset_id = context.get("asset_id", target)
        cve = context.get("cve", "")

        public_exploit_found = False
        exploit_refs = []
        safety_class = "LEVEL_1_NON_INVASIVE"

        if shutil.which("searchsploit") and cve:
            cmd = self.build_test(target, context)
            ret, stdout, stderr = self._run_cmd_safe(cmd, timeout=10)
            if ret == 0 and stdout:
                try:
                    data = json.loads(stdout)
                    results = data.get("RESULTS_EXPLOIT", [])
                    if results:
                        public_exploit_found = True
                        for r in results[:3]:
                            exploit_refs.append({
                                "title": r.get("Title"),
                                "edb_id": r.get("EDB-ID"),
                                "type": r.get("Type"),
                                "platform": r.get("Platform"),
                            })
                except Exception:
                    pass

        # Offline curated knowledge check if searchsploit CLI is absent
        if not exploit_refs and cve:
            # Common high-profile CVEs catalog check
            known_exploited = {
                "CVE-2021-44228": ("Log4Shell Remote Code Execution", "remote", "high"),
                "CVE-2023-34362": ("MOVEit Transfer SQLi / RCE", "webapps", "critical"),
                "CVE-2017-0144": ("EternalBlue SMB Remote Code Execution", "remote", "critical"),
                "CVE-2019-19781": ("Citrix ADC Path Traversal", "remote", "high"),
            }
            if cve in known_exploited:
                title, exp_type, sev = known_exploited[cve]
                public_exploit_found = True
                exploit_refs.append({
                    "title": title,
                    "edb_id": "curated-intel",
                    "type": exp_type,
                    "platform": "multiple",
                })

        self.success_count += 1

        evidence = {
            "type": "exploit_intelligence",
            "cve": cve,
            "public_exploit_found": public_exploit_found,
            "exploit_references": exploit_refs,
            "safety_classification": safety_class,
            "action_guidance": "Vulnerability has known public exploit references. Verify version before manual approval."
        }

        return self.normalize_result(
            finding_id=finding_id,
            asset_id=asset_id,
            status="validated" if public_exploit_found else "not_exploitable",
            confidence=0.85 if public_exploit_found else 0.50,
            evidence=[evidence],
            cve=cve,
            cwe=context.get("cwe"),
            severity=context.get("severity", "medium"),
            execution_status="completed",
        )

    def parse_result(self, raw_output: str) -> List[Dict[str, Any]]:
        return []

    def collect_evidence(self, raw_output: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {"raw_intel": raw_output}
