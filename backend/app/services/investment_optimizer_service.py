"""
ARGOLOCK V1.7 Investment Optimization & Remediation Prioritization Engine
Calculates Remediation ROI (Risk Reduction vs Implementation Cost) without making savings claims.
All figures are explicitly labeled as OBSERVED, ASSUMED, or MODELED.
Costs are derived from user-supplied hourly engineering rates and include uncertainty intervals.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.models.v1_7_models import (
    FigureOrigin,
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
    Evaluates remediation actions and prioritizes them based on technical ROI:
    ROI = Modeled Risk Reduction Points / Cost Index
    Takes hourly cost from user input, emits uncertainty ranges, and makes no savings claims.
    """

    @classmethod
    def generate_plan(
        cls,
        scan_id: str,
        initial_risk_score: float,
        findings: List[Dict[str, Any]],
        user_hourly_rate: float = 120.0,
        hourly_downtime_cost_usd: float = 5000.0,
    ) -> InvestmentOptimizationPlan:
        actions: List[RemediationActionItem] = []

        if not findings:
            return InvestmentOptimizationPlan(
                scan_id=scan_id,
                initial_risk_score=initial_risk_score,
                projected_residual_risk=0.0,
                total_risk_reduction=0.0,
                user_hourly_rate=user_hourly_rate,
                total_effort_range={"min_hours": 0, "expected_hours": 0, "max_hours": 0},
                total_cost_range={"min_usd": 0.0, "expected_usd": 0.0, "max_usd": 0.0},
                modeled_loss_reduction_range={"min_usd": 0.0, "expected_usd": 0.0, "max_usd": 0.0},
                assumptions=[
                    "No findings identified in assessment.",
                    f"User hourly engineer rate: ${user_hourly_rate:,.2f}/hr.",
                ],
                savings_claim_notice="No direct financial savings claimed. Figures represent modeled reduction in technical risk points and potential loss exposure.",
                actions=[],
                generated_at=utc_now_iso(),
            )

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

            exp_risk_reduction = round(matched["risk_reduction"] * multiplier, 1)
            min_risk_reduction = round(exp_risk_reduction * 0.75, 1)
            max_risk_reduction = round(min(100.0, exp_risk_reduction * 1.25), 1)

            cost_idx = matched["cost_index"]
            roi = round(exp_risk_reduction / cost_idx, 2)

            # Effort ranges (ASSUMED benchmark with uncertainty interval)
            exp_hours = matched["hours"]
            min_hours = max(1, int(round(exp_hours * 0.7)))
            max_hours = int(round(exp_hours * 1.5))

            # Financial cost derived from user-supplied hourly rate
            min_cost = round(min_hours * user_hourly_rate, 2)
            exp_cost = round(exp_hours * user_hourly_rate, 2)
            max_cost = round(max_hours * user_hourly_rate, 2)

            # Assign Priority
            if roi >= 15.0 or sev == "critical":
                priority = RemediationPriority.P1
            elif roi >= 10.0 or sev == "high":
                priority = RemediationPriority.P2
            elif roi >= 6.0:
                priority = RemediationPriority.P3
            else:
                priority = RemediationPriority.P4

            # Provenance tagging
            figure_provenance = {
                "user_hourly_rate": FigureOrigin.ASSUMED,
                "effort_range": FigureOrigin.ASSUMED,
                "cost_range": FigureOrigin.MODELED,
                "risk_reduction_range": FigureOrigin.MODELED,
                "roi_score": FigureOrigin.MODELED,
            }

            actions.append(RemediationActionItem(
                finding_id=f_id,
                title=f"Remediate {f.get('title')}",
                recommended_control=matched["control"],
                estimated_cost=matched["cost"],
                cost_index=cost_idx,
                user_hourly_rate=user_hourly_rate,
                effort_hours=exp_hours,
                effort_range={
                    "min_hours": min_hours,
                    "expected_hours": exp_hours,
                    "max_hours": max_hours,
                },
                cost_range={
                    "min_cost_usd": min_cost,
                    "expected_cost_usd": exp_cost,
                    "max_cost_usd": max_cost,
                },
                risk_reduction_points=exp_risk_reduction,
                risk_reduction_range={
                    "min_points": min_risk_reduction,
                    "expected_points": exp_risk_reduction,
                    "max_points": max_risk_reduction,
                },
                residual_risk_points=max(0.0, round(initial_risk_score - exp_risk_reduction, 1)),
                roi_score=roi,
                priority=priority,
                compliance_mappings=matched["compliance"],
                figure_provenance=figure_provenance,
            ))

        # Sort actions by Priority (P1 -> P4) then by ROI descending
        priority_order = {
            RemediationPriority.P1: 0,
            RemediationPriority.P2: 1,
            RemediationPriority.P3: 2,
            RemediationPriority.P4: 3,
        }
        actions.sort(key=lambda x: (priority_order[x.priority], -x.roi_score))

        # Cumulative risk reduction (capped at 90% of initial score)
        top_actions = actions[:5]
        total_reduction = min(initial_risk_score * 0.9, sum(a.risk_reduction_points for a in top_actions))
        projected_residual = max(0.0, round(initial_risk_score - total_reduction, 1))

        # Aggregate ranges across top actions
        tot_min_hours = sum(a.effort_range.get("min_hours", a.effort_hours) for a in top_actions)
        tot_exp_hours = sum(a.effort_hours for a in top_actions)
        tot_max_hours = sum(a.effort_range.get("max_hours", a.effort_hours) for a in top_actions)

        tot_min_cost = round(tot_min_hours * user_hourly_rate, 2)
        tot_exp_cost = round(tot_exp_hours * user_hourly_rate, 2)
        tot_max_cost = round(tot_max_hours * user_hourly_rate, 2)

        # Modeled potential downtime loss reduction (NO savings claim - clearly labeled loss exposure reduction)
        mitigated_downtime_hours_exp = round(tot_exp_hours * 0.5, 1)
        mitigated_downtime_hours_min = round(tot_min_hours * 0.3, 1)
        mitigated_downtime_hours_max = round(tot_max_hours * 0.8, 1)

        modeled_loss_reduction = {
            "min_usd": round(mitigated_downtime_hours_min * hourly_downtime_cost_usd, 2),
            "expected_usd": round(mitigated_downtime_hours_exp * hourly_downtime_cost_usd, 2),
            "max_usd": round(mitigated_downtime_hours_max * hourly_downtime_cost_usd, 2),
        }

        assumptions = [
            f"Engineer hourly billing rate: ${user_hourly_rate:,.2f}/hr (user-supplied).",
            f"Remediation effort estimation range: [-30%, +50%] uncertainty band.",
            "Modeled risk reduction capped at 90% of initial scan risk score.",
            "Remediation of top prioritized findings completely eliminates corresponding vulnerability attack vectors without regression.",
            "No direct financial savings claimed. Figures represent modeled technical risk reduction and potential incident downtime exposure mitigation.",
        ]

        return InvestmentOptimizationPlan(
            scan_id=scan_id,
            initial_risk_score=initial_risk_score,
            projected_residual_risk=projected_residual,
            total_risk_reduction=round(total_reduction, 1),
            user_hourly_rate=user_hourly_rate,
            total_effort_range={
                "min_hours": tot_min_hours,
                "expected_hours": tot_exp_hours,
                "max_hours": tot_max_hours,
            },
            total_cost_range={
                "min_usd": tot_min_cost,
                "expected_usd": tot_exp_cost,
                "max_usd": tot_max_cost,
            },
            modeled_loss_reduction_range=modeled_loss_reduction,
            assumptions=assumptions,
            savings_claim_notice="No direct financial savings claimed. Figures represent modeled reduction in technical risk points and potential loss exposure.",
            actions=actions,
            generated_at=utc_now_iso(),
        )
