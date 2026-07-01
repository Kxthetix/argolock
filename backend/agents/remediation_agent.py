"""
Agent 3: Root Cause & Fix Agent
- Analyzes each vulnerability's root cause
- Generates step-by-step remediation
- Provides secure code examples
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from loguru import logger

from agents.base_agent import BaseAgent

SYSTEM_PROMPT = """You are a senior application security engineer and secure coding expert.
For each vulnerability, provide:
1. Root cause analysis — why this vulnerability exists technically
2. Step-by-step remediation — clear numbered steps to fix it
3. A secure code example — show the fix in code (relevant language/framework)
4. References — CVE, CWE, OWASP links

Be specific, actionable, and technically precise.
Return JSON with remediation object for each finding."""


class RemediationAgent(BaseAgent):
    prompt_file = "remediation_advice.txt"

    def get_system_prompt(self) -> str:
        """Return the loaded system prompt template or the fallback prompt."""
        return self._prompt_template or SYSTEM_PROMPT

    async def remediate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate root cause and remediation for each finding."""
        if not findings:
            return []

        # Only generate remediation for non-info findings
        significant = [f for f in findings if f.get("severity", "info").lower() != "info"]
        info_findings = [f for f in findings if f.get("severity", "info").lower() == "info"]

        remediated = []
        # Process one by one for high/critical, in chunks for others
        critical_high = [f for f in significant if f.get("severity", "").lower() in ("critical", "high")]
        others = [f for f in significant if f.get("severity", "").lower() not in ("critical", "high")]

        for finding in critical_high:
            logger.info(f"RemediationAgent: Processing {finding.get('severity')} finding: {finding.get('title', '')[:50]}")
            try:
                finding = await self._remediate_single(finding)
            except Exception as e:
                logger.error(f"Remediation failed for {finding.get('title')}: {e}")
            remediated.append(finding)

        # Process medium/low in batches
        for chunk in self._chunk_findings(others, chunk_size=5):
            try:
                chunk = await self._remediate_batch(chunk)
            except Exception as e:
                logger.error(f"Batch remediation failed: {e}")
            remediated.extend(chunk)

        return remediated + info_findings

    async def _remediate_single(self, finding: Dict) -> Dict:
        """Generate detailed remediation for a single high/critical finding."""
        prompt = f"""Vulnerability: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'unknown')}
OWASP: {finding.get('owasp_category', 'Unknown')}
Affected Endpoint: {finding.get('affected_endpoint', '')}
Description: {finding.get('description', '')}

Provide:
1. root_cause: Technical explanation of why this vulnerability exists
2. fix_steps: Array of numbered remediation steps
3. secure_code_example: Code showing the fix
4. references: Array of OWASP/CVE/CWE links

Return as JSON: {{"root_cause": "...", "fix_steps": [...], "secure_code_example": "...", "references": [...]}}"""

        response = await self._complete(prompt, system=self.get_system_prompt())
        result = self._extract_json(response)

        if isinstance(result, dict):
            finding["remediation"] = result
        return finding

    async def _remediate_batch(self, findings: List[Dict]) -> List[Dict]:
        """Generate brief remediations for a batch of lower-severity findings."""
        prompt = f"""Generate remediation for these vulnerabilities:
{json.dumps([{"title": f.get("title"), "severity": f.get("severity"), "description": f.get("description", "")[:200]} for f in findings], indent=2)}

For each, provide a JSON object with: root_cause, fix_steps (array), references (array).
Return as JSON array matching the input order."""

        response = await self._complete(prompt, system=self.get_system_prompt())
        remediations = self._extract_json(response)

        if isinstance(remediations, list) and len(remediations) == len(findings):
            for i, finding in enumerate(findings):
                if isinstance(remediations[i], dict):
                    finding["remediation"] = remediations[i]

        return findings
