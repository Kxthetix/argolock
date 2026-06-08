"""Nuclei tool — template-based vulnerability scanning."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from loguru import logger

from app.config import settings
from tools.base_tool import BaseTool


class NucleiTool(BaseTool):
    name = "nuclei"
    docker_image = settings.nuclei_docker_image

    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        severities = options.get("severities", ["critical", "high", "medium"])
        severity_str = ",".join(severities)

        cmd = [
            "nuclei",
            "-target", target,
            "-severity", severity_str,
            "-jsonl",                   # JSONL output per finding
            "-silent",                  # No banner
            "-no-color",
            "-timeout", "10",           # Per-request timeout
            "-rate-limit", "50",        # Rate limit req/sec
            "-bulk-size", "25",
            "-concurrency", "10",
            "-update-templates",        # Always use latest templates
        ]
        return cmd

    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        """Parse Nuclei JSONL output — each line is a finding."""
        findings = []

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                parsed = {
                    "template_id": finding.get("template-id", ""),
                    "template_name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", "info"),
                    "description": finding.get("info", {}).get("description", ""),
                    "tags": finding.get("info", {}).get("tags", []),
                    "classification": finding.get("info", {}).get("classification", {}),
                    "matched_at": finding.get("matched-at", target),
                    "endpoint": finding.get("matched-at", target),
                    "extracted_results": finding.get("extracted-results", []),
                    "request": finding.get("request", ""),
                    "response": finding.get("response", "")[:2000],  # Cap response size
                    "curl_command": finding.get("curl-command", ""),
                    "matcher_name": finding.get("matcher-name", ""),
                    "type": finding.get("type", ""),
                    "host": finding.get("host", target),
                    "ip": finding.get("ip", ""),
                    "timestamp": finding.get("timestamp", ""),
                    "references": finding.get("info", {}).get("reference", []),
                    "cvss_score": self._extract_cvss(finding),
                    "cve_ids": self._extract_cves(finding),
                }
                findings.append(parsed)
            except json.JSONDecodeError:
                logger.warning(f"Nuclei: failed to parse JSON line: {line[:200]}")
                continue

        return {
            "findings": findings,
            "total": len(findings),
        }

    def _extract_cvss(self, finding: dict) -> float:
        """Extract CVSS score from Nuclei finding."""
        classification = finding.get("info", {}).get("classification", {})
        if "cvss-score" in classification:
            try:
                return float(classification["cvss-score"])
            except (ValueError, TypeError):
                pass
        # Map severity to default score
        sev_map = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.5, "info": 0.0}
        sev = finding.get("info", {}).get("severity", "info").lower()
        return sev_map.get(sev, 0.0)

    def _extract_cves(self, finding: dict) -> List[str]:
        """Extract CVE IDs from Nuclei finding."""
        classification = finding.get("info", {}).get("classification", {})
        cves = classification.get("cve-id", [])
        if isinstance(cves, str):
            return [cves]
        return cves or []
