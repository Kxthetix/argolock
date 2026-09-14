"""
ARGOLOCK V1.7 Cyber Risk Quantification Engine
Calculates organizational risk score incorporating severity, exploitability,
asset criticality, exposure, business impact, threat relevance, and confidence.
"""
from __future__ import annotations

from typing import Any, Dict, List
from app.models.v1_7_models import CyberRiskScore, utc_now_iso


class CyberRiskEngine:
    """
    Computes calibrated cyber risk score:
    Risk = Severity × Exploitability × Asset Criticality × Exposure × Business Impact × Threat Relevance × Confidence
    """

    SEVERITY_WEIGHTS = {
        "critical": 10.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "info": 0.5,
    }

    @classmethod
    def calculate_scan_risk(
        cls,
        scan_id: str,
        findings: List[Dict[str, Any]],
        asset_criticality: float = 1.2, # 0.5 (dev) to 2.0 (crown jewels / payment / auth)
        exposure_factor: float = 1.3,   # 1.0 (internal) to 1.5 (public internet-facing)
        threat_relevance: float = 1.1,  # 1.0 to 1.5 (active CISA KEV / public weaponized PoCs)
    ) -> CyberRiskScore:
        if not findings:
            return CyberRiskScore(
                scan_id=scan_id,
                score=0.0,
                rating="Informational",
                severity_factor=0.0,
                exploitability_factor=0.0,
                asset_criticality_factor=asset_criticality,
                exposure_factor=exposure_factor,
                business_impact_factor=1.0,
                threat_relevance_factor=threat_relevance,
                confidence_factor=1.0,
                calculation_breakdown={"total_findings": 0, "critical_count": 0, "high_count": 0}
            )

        # 1. Base severity calculation
        total_sev = sum(cls.SEVERITY_WEIGHTS.get((f.get("severity") or "info").lower(), 1.0) for f in findings)
        max_possible = len(findings) * 10.0
        avg_sev_norm = (total_sev / max_possible) if max_possible > 0 else 0.0 # 0.0 - 1.0

        # 2. Exploitability & confirmation factor
        confirmed_count = sum(1 for f in findings if f.get("confirmed", True))
        exploitability = round(confirmed_count / len(findings), 2) if findings else 0.5

        # 3. Confidence factor
        avg_confidence = round(
            sum(float(f.get("confidence", 0.85) or 0.85) for f in findings) / len(findings), 2
        ) if findings else 0.8

        # 4. Business impact factor based on vulnerability types
        has_rce_or_takeover = any(
            any(k in (f.get("title") or "").lower() for k in ["rce", "command", "takeover", "auth bypass", "sqli"])
            for f in findings
        )
        business_impact = 1.8 if has_rce_or_takeover else 1.2

        # 5. Combined Multiplicative Calculation
        # Raw composite index
        raw_composite = (
            (avg_sev_norm * 40.0) +
            (min(total_sev, 50.0) * 0.4)
        ) * exploitability * asset_criticality * exposure_factor * business_impact * threat_relevance * avg_confidence

        # Calibrate into 0 - 100 range cleanly
        calibrated_score = round(min(100.0, max(0.0, raw_composite)), 1)

        # Rating tier
        if calibrated_score >= 80.0:
            rating = "CRITICAL"
        elif calibrated_score >= 60.0:
            rating = "HIGH"
        elif calibrated_score >= 40.0:
            rating = "MEDIUM"
        elif calibrated_score >= 15.0:
            rating = "LOW"
        else:
            rating = "INFORMATIONAL"

        return CyberRiskScore(
            scan_id=scan_id,
            score=calibrated_score,
            rating=rating,
            severity_factor=round(avg_sev_norm * 10.0, 1),
            exploitability_factor=exploitability,
            asset_criticality_factor=asset_criticality,
            exposure_factor=exposure_factor,
            business_impact_factor=business_impact,
            threat_relevance_factor=threat_relevance,
            confidence_factor=avg_confidence,
            calculation_breakdown={
                "total_findings": len(findings),
                "confirmed_count": confirmed_count,
                "asset_criticality_multiplier": asset_criticality,
                "exposure_multiplier": exposure_factor,
                "threat_relevance_multiplier": threat_relevance,
                "raw_composite": round(raw_composite, 2),
            },
            calculated_at=utc_now_iso(),
        )
