"""
ARGOLOCK V1.7 Investment Optimization & Remediation ROI Engine
Calculates Remediation ROI (Risk Reduction vs Implementation Cost)
and sequences fixes into prioritized tiers (P1 to P4) for optimal risk reduction.
"""
from __future__ import annotations

from typing import Any, Dict, List
from app.models.v1_7_models import (
    InvestmentOptimizationPlan,
    RemediationActionItem,
    RemediationPriority,
    utc_now_iso,
)


CONTROL_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "sql injection": {
        "control": "Implement Parameterized Queries & Prepared Statements",
        "cost": "Medium",
        "cost_index": 2.0,
        "risk_reduction": 28.0,
        "hours": 12,
        "compliance": ["OWASP A03:2021", "PCI-DSS 6.5.1", "SOC2 CC6.1"],
    },
    "idor": {
        "control": "Enforce Server-Side Object-Level Authorization & RBAC Checks",
        "cost": "Medium",
        "cost_index": 2.2,
        "risk_reduction": 25.0,
        "hours": 16,
        "compliance": ["OWASP A01:2021", "ISO 27001 A.9.4", "SOC2 CC6.3"],
    },
    "xss": {
        "control": "Context-Aware Context Encoding & Strict Content-Security-Policy (CSP)",
        "cost": "Low",
        "cost_index": 1.2,
        "risk_reduction": 18.0,
        "hours": 6,
        "compliance": ["OWASP A03:2021", "PCI-DSS 6.5.7"],
    },
    "ssrf": {
        "control": "Whitelist Allowed Outbound IPs & Block Access to Cloud Metadata 169.254.169.254",
        "cost": "Low",
        "cost_index": 1.0,
        "risk_reduction": 22.0,
        "hours": 4,
        "compliance": ["OWASP A10:2021", "CIS AWS Benchmark 1.16"],
    },
    "dmarc": {
        "control": "Publish Strict DMARC Policy (p=reject) with Validated SPF & DKIM Records",
        "cost": "Low",
        "cost_index": 0.8,
        "risk_reduction": 12.0,
        "hours": 2,
        "compliance": ["OWASP A05:2021", "M3AAWG Best Practice"],
    },
    "tls": {
        "control": "Enforce TLS 1.3, Deprecate Weak Ciphers & Enable HSTS with Preload",
        "cost": "Low",
        "cost_index": 0.9,
        "risk_reduction": 10.0,
        "hours": 3,
        "compliance": ["OWASP A02:2021", "PCI-DSS 4.1"],
    },
    "default": {
        "control": "Implement Hardened Configuration Baseline & Least Privilege Access",
        "cost": "Medium",
        "cost_index": 1.5,
        "risk_reduction": 14.0,
        "hours": 8,
        "compliance": ["OWASP Top 10", "ISO 27001 A.12"],
    },
}


class InvestmentOptimizer:
    """
    Evaluates remediation actions and prioritizes them based on net ROI:
    ROI = Risk Reduction Points / Cost Index
    """

    @classmethod
    def generate_plan(
        cls,
        scan_id: str,
        initial_risk_score: float,
        findings: List[Dict[str, Any]],
    ) -> InvestmentOptimizationPlan:
        actions: List[RemediationActionItem] = []

        for f in findings:
            title = (f.get("title") or "Security Finding").lower()
            f_id = f.get("id")

            # Match control playbook
            matched = CONTROL_PLAYBOOKS["default"]
            for key, pb in CONTROL_PLAYBOOKS.items():
                if key in title:
                    matched = pb
                    break

            sev = (f.get("severity") or "medium").lower()
            multiplier = 1.6 if sev == "critical" else 1.3 if sev == "high" else 1.0 if sev == "medium" else 0.5
            
            risk_reduction = round(matched["risk_reduction"] * multiplier, 1)
            cost_idx = matched["cost_index"]
            roi = round(risk_reduction / cost_idx, 2)

            # Assign Priority
            if roi >= 15.0 or sev == "critical":
                priority = RemediationPriority.P1
            elif roi >= 10.0 or sev == "high":
                priority = RemediationPriority.P2
            elif roi >= 6.0:
                priority = RemediationPriority.P3
            else:
                priority = RemediationPriority.P4

            actions.append(RemediationActionItem(
                finding_id=f_id,
                title=f"Remediate {f.get('title')}",
                recommended_control=matched["control"],
                estimated_cost=matched["cost"],
                cost_index=cost_idx,
                risk_reduction_points=risk_reduction,
                residual_risk_points=max(0.0, round(initial_risk_score - risk_reduction, 1)),
                roi_score=roi,
                priority=priority,
                effort_hours=matched["hours"],
                compliance_mappings=matched["compliance"],
            ))

        # Sort actions by Priority (P1 -> P4) then by ROI descending
        priority_order = {RemediationPriority.P1: 0, RemediationPriority.P2: 1, RemediationPriority.P3: 2, RemediationPriority.P4: 3}
        actions.sort(key=lambda x: (priority_order[x.priority], -x.roi_score))

        # Cumulative risk reduction
        total_reduction = min(initial_risk_score * 0.9, sum(a.risk_reduction_points for a in actions[:5]))
        projected_residual = max(5.0, round(initial_risk_score - total_reduction, 1))

        return InvestmentOptimizationPlan(
            scan_id=scan_id,
            initial_risk_score=initial_risk_score,
            projected_residual_risk=projected_residual,
            total_risk_reduction=round(total_reduction, 1),
            actions=actions,
            generated_at=utc_now_iso(),
        )
