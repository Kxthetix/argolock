"""
Agent 4: Report Generator
- Generates executive summary
- Assembles full professional report
- Triggers PDF and JSON export
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

# pyrefly: ignore [missing-import]
from loguru import logger

from agents.base_agent import BaseAgent
from reports.pdf_generator import generate_pdf

SYSTEM_PROMPT = """You are a cybersecurity report writer specializing in bug bounty and penetration test reports.
Write in a professional, clear style suitable for both technical and executive audiences.
Use HackerOne bug bounty report format conventions."""


class ReportAgent(BaseAgent):
    prompt_file = "report_generation.txt"

    def get_system_prompt(self) -> str:
        """Return the loaded system prompt template or the fallback prompt."""
        return self._prompt_template or SYSTEM_PROMPT

    async def generate(
        self,
        scan_id: str,
        scan_doc: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate the full security report."""
        target = scan_doc["scope"]["target"]
        total = len(findings)
        severities = {
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
        }

        # Calculate overall risk score
        risk_score = self._calculate_risk_score(findings)
        risk_rating = self._risk_rating(risk_score)

        # Generate executive summary via AI
        logger.info("ReportAgent: Generating executive summary...")
        executive_summary = await self._generate_executive_summary(
            target, severities, total, findings[:5]
        )

        # Generate JSON report
        report_data = {
            "report_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "executive_summary": executive_summary,
            "risk_score": risk_score,
            "risk_rating": risk_rating,
            "statistics": {
                "total_findings": total,
                **severities,
                "tools_used": list(scan_doc.get("tool_results", {}).keys()),
            },
            "methodology": self._methodology_text(),
            "findings": findings,
            "scope": scan_doc["scope"],
        }

        # Save JSON report
        from app.config import settings
        os.makedirs(settings.reports_dir, exist_ok=True)
        json_path = os.path.join(settings.reports_dir, f"argolock_report_{scan_id}.json")
        with open(json_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        # Generate PDF
        pdf_path = None
        try:
            pdf_path = await generate_pdf(report_data, scan_id)
            logger.info(f"ReportAgent: PDF generated at {pdf_path}")
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")

        return {
            "id": report_data["report_id"],
            "scan_id": scan_id,
            "format": "both" if pdf_path else "json",
            "generated_at": report_data["generated_at"],
            "pdf_path": pdf_path,
            "json_path": json_path,
            "executive_summary": executive_summary,
            "total_findings": total,
            "risk_score": risk_score,
            "risk_rating": risk_rating,
        }

    async def _generate_executive_summary(
        self,
        target: str,
        severities: Dict,
        total: int,
        top_findings: List[Dict],
    ) -> str:
        prompt = f"""Write a professional executive summary for a penetration test report.

Target: {target}
Assessment Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
Total Findings: {total}
Critical: {severities['critical']} | High: {severities['high']} | Medium: {severities['medium']} | Low: {severities['low']}

Top findings overview:
{json.dumps([{"title": f.get("title"), "severity": f.get("severity"), "endpoint": f.get("affected_endpoint")} for f in top_findings], indent=2)}

Write 3-4 paragraphs covering:
1. Overall security posture
2. Most critical risks and business impact
3. Recommended immediate actions
4. Long-term security recommendations

Keep it professional, concise, and action-oriented."""

        try:
            return await self._complete(prompt, system=self.get_system_prompt())
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return f"Security assessment of {target} identified {total} vulnerabilities requiring attention."

    def _calculate_risk_score(self, findings: List[Dict]) -> float:
        """Calculate overall risk score (0-100) from findings."""
        if not findings:
            return 0.0
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        max_possible = len(findings) * 10
        total = sum(weights.get(f.get("severity", "info").lower(), 0) for f in findings)
        return round(min((total / max(max_possible, 1)) * 100, 100), 1)

    def _risk_rating(self, score: float) -> str:
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        return "Informational"

    def _methodology_text(self) -> str:
        return """This assessment was conducted using an automated AI-powered VAPT pipeline.
Tools used: Nmap (port scanning), Subfinder (subdomain enumeration), WhatWeb (fingerprinting),
Nuclei (template-based scanning), Nikto (web server analysis), OWASP ZAP (active scanning),
and SQLmap (SQL injection detection in safe mode).
All findings were analyzed, deduplicated, and enriched by AI agents using OWASP Top 10 2021 classification."""
