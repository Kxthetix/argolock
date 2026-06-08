"""
Agent 2: Risk Scoring Agent
- Calculates CVSS 3.1 base scores
- Uses rule-based logic + AI refinement
- Prioritizes findings by exploitability and impact
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from loguru import logger

from agents.base_agent import BaseAgent

SYSTEM_PROMPT = """You are a CVSS 3.1 scoring expert and security risk analyst.
Your task is to calculate accurate CVSS 3.1 base scores for vulnerabilities.

For each finding, determine the CVSS vector components:
- AV (Attack Vector): N=Network, A=Adjacent, L=Local, P=Physical
- AC (Attack Complexity): L=Low, H=High  
- PR (Privileges Required): N=None, L=Low, H=High
- UI (User Interaction): N=None, R=Required
- S (Scope): U=Unchanged, C=Changed
- C (Confidentiality Impact): N=None, L=Low, H=High
- I (Integrity Impact): N=None, L=Low, H=High
- A (Availability Impact): N=None, L=Low, H=High

Then calculate the base score (0.0-10.0) using CVSS 3.1 formula.

Return JSON with cvss_score and cvss_vector per finding."""

# ── Rule-based CVSS estimation ────────────────────────────────────────────────
SEVERITY_BASE_SCORES = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}

VULN_TYPE_VECTORS = {
    "sql injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "xss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "rce": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "ssrf": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "N"},
    "lfi": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "open redirect": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "default": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
}


def _rule_based_score(finding: Dict) -> tuple[float, Dict]:
    """Quick rule-based CVSS estimation before AI refinement."""
    title_lower = (finding.get("title") or "").lower()
    sev = finding.get("severity", "info").lower()

    # Match known vuln type
    vector = VULN_TYPE_VECTORS["default"]
    for vuln_type, v in VULN_TYPE_VECTORS.items():
        if vuln_type in title_lower:
            vector = v
            break

    # Base score from severity if we have it
    if finding.get("cvss_score", 0) > 0:
        return finding["cvss_score"], vector

    return SEVERITY_BASE_SCORES.get(sev, 0.0), vector


class RiskScoringAgent(BaseAgent):

    async def score(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score all findings with CVSS 3.1 scores."""
        if not findings:
            return []

        scored = []
        chunks = self._chunk_findings(findings, chunk_size=10)

        for i, chunk in enumerate(chunks):
            logger.info(f"RiskScoringAgent: Scoring chunk {i+1}/{len(chunks)}")
            try:
                scored_chunk = await self._score_chunk(chunk)
                scored.extend(scored_chunk)
            except Exception as e:
                logger.error(f"RiskScoringAgent chunk {i+1} failed: {e}")
                # Fallback to rule-based
                for f in chunk:
                    score, vector = _rule_based_score(f)
                    f["cvss_score"] = score
                    f["cvss"] = {"vector": vector, "base_score": score}
                    scored.append(f)

        # Sort by CVSS score descending
        scored.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        return scored

    async def _score_chunk(self, chunk: List[Dict]) -> List[Dict]:
        """Use AI to refine CVSS scores for a chunk of findings."""
        # Apply rule-based scores first
        for f in chunk:
            score, vector = _rule_based_score(f)
            f.setdefault("cvss_score", score)
            f.setdefault("cvss", {"vector": vector, "base_score": score})

        prompt = f"""Score these security findings with accurate CVSS 3.1 base scores.

Findings:
{json.dumps(chunk, indent=2)[:6000]}

For each finding, update the cvss_score (0.0-10.0) and cvss.vector based on the actual vulnerability details.
Return the same JSON array with updated cvss_score and cvss fields.
Return ONLY valid JSON array."""

        response = await self._complete(prompt, system=SYSTEM_PROMPT)
        result = self._extract_json(response)

        if isinstance(result, list) and len(result) == len(chunk):
            return result

        # If AI response doesn't match, return rule-based scores
        return chunk
