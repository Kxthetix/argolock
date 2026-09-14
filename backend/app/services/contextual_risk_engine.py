"""Contextual Cyber Risk Quantification Engine for ARGOLOCK NET v1.6."""
from __future__ import annotations

from typing import Any, Dict, Optional
from loguru import logger

from app.models.vapt_models import ContextualRiskScore, ExploitabilityAssessment, ValidationStatus


class ContextualRiskEngine:
    """Calculates explainable enterprise cyber risk by correlating technical severity,

    exploitability intelligence, network exposure, asset criticality, and attack paths.
    """

    def calculate_risk(
        self,
        finding: Dict[str, Any],
        exploit_assessment: ExploitabilityAssessment,
        asset_context: Optional[Dict[str, Any]] = None,
        attack_path_multiplier: float = 1.0,
    ) -> ContextualRiskScore:
        finding_id = finding.get("id", "unknown")
        cvss_score = float(finding.get("cvss_score") or 5.0)

        # 1. Technical Severity Factor (0 - 10)
        tech_severity = cvss_score

        # 2. Exploitability Factor (0 - 10)
        exp_val = exploit_assessment.exploitability_level
        exp_level = exp_val.value if hasattr(exp_val, "value") else str(exp_val).lower()
        exp_map = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.5,
            "none": 0.5,
        }
        exploit_factor = exp_map.get(exp_level, 5.0)

        # 3. Exposure Factor (0 - 10)
        asset_context = asset_context or {}
        exposure_type = asset_context.get("network_exposure", exploit_assessment.network_exposure)
        if exposure_type == "external":
            exposure_factor = 10.0
        elif exposure_type == "adjacent":
            exposure_factor = 6.0
        else:
            exposure_factor = 3.0

        # 4. Business Impact Factor (0 - 10) based on Asset Criticality
        criticality = asset_context.get("asset_criticality", "medium").lower()
        crit_map = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
        }
        business_impact = crit_map.get(criticality, 5.0)

        # 5. Attack Path Multiplier (1.0 to 1.5)
        path_multiplier = max(1.0, min(1.5, float(attack_path_multiplier)))

        # 6. Raw Weighted Score (Scale 0 - 100)
        # Formula: Technical (25%) + Exploitability (25%) + Exposure (25%) + Business Impact (25%) * Path Multiplier
        base_score = (
            (tech_severity * 2.5) +
            (exploit_factor * 2.5) +
            (exposure_factor * 2.5) +
            (business_impact * 2.5)
        )

        final_score = min(100.0, round(base_score * path_multiplier, 1))

        # Determine Risk Tier
        if final_score >= 85.0:
            tier = "critical"
        elif final_score >= 70.0:
            tier = "high"
        elif final_score >= 45.0:
            tier = "medium"
        elif final_score >= 20.0:
            tier = "low"
        else:
            tier = "info"

        explanation = {
            "technical_severity_contrib": f"{tech_severity} / 10 (Weight 25%)",
            "exploitability_contrib": f"{exploit_factor} / 10 (Weight 25%, Level: {exp_level.upper()})",
            "exposure_contrib": f"{exposure_factor} / 10 (Weight 25%, Type: {exposure_type.upper()})",
            "business_impact_contrib": f"{business_impact} / 10 (Weight 25%, Criticality: {criticality.upper()})",
            "attack_path_multiplier": f"x{path_multiplier} (Path to Crown Jewels)",
            "summary": (
                f"Assigned {tier.upper()} risk ({final_score}/100) due to "
                f"{exp_level} exploitability on {exposure_type} asset with {criticality} business impact."
            )
        }

        return ContextualRiskScore(
            finding_id=finding_id,
            technical_severity=tech_severity,
            exploitability_factor=exploit_factor,
            exposure_factor=exposure_factor,
            business_impact_factor=business_impact,
            attack_path_multiplier=path_multiplier,
            final_risk_score=final_score,
            risk_tier=tier,
            explanation=explanation,
        )


contextual_risk_engine = ContextualRiskEngine()
