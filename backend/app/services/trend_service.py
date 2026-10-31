"""
ARGOLOCK V1.7 Assessment Trend & Posture Service
Aggregates historical assessment data across scans to compute risk trajectory,
Mean Time to Remediate (MTTR), and verified risk reduction over time.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.v1_7_models import (
    AssessmentTrendPoint,
    AssessmentTrendView,
    FigureOrigin,
    utc_now_iso,
)
from app.services.cyber_risk_service import CyberRiskEngine


class TrendService:
    """Computes longitudinal risk trends and MTTR across assessments."""

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        from app.database import get_db
        return get_db()

    async def get_target_trend_view(
        self,
        target: str,
        limit: int = 10,
    ) -> AssessmentTrendView:
        """
        Aggregate historical assessment points for target host or application.
        Computes risk trajectory, MTTR, and verified risk reduction over time.
        """
        db = self._get_db()

        # Find historical scans matching target
        scan_query: Dict[str, Any] = {}
        if target and target != "*":
            scan_query = {
                "$or": [
                    {"target": target},
                    {"target": {"$regex": target, "$options": "i"}},
                    {"scope.target": target},
                    {"scope.target": {"$regex": target, "$options": "i"}},
                ]
            }

        scans_cursor = db["scans"].find(scan_query, {"_id": 0}).sort("created_at", 1).limit(limit)
        scans = await scans_cursor.to_list(length=limit)

        history_points: List[AssessmentTrendPoint] = []
        all_resolved_durations_hours: List[float] = []
        total_verified_reduction = 0.0

        for s in scans:
            scan_id = s.get("id") or s.get("scan_id") or "scan-unknown"
            created_at = s.get("created_at") or utc_now_iso()

            # Retrieve findings for this scan
            findings_cursor = db["findings"].find({"scan_id": scan_id}, {"_id": 0})
            findings = await findings_cursor.to_list(length=200)

            # Severity counts
            sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            resolved_count = 0

            for f in findings:
                sev = (f.get("severity") or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

                retest_status = str(f.get("retest_status", "")).lower()
                val_status = str(f.get("validation_status", "")).lower()
                is_resolved = (retest_status == "resolved" or val_status == "not_exploitable")

                if is_resolved:
                    resolved_count += 1
                    # Accumulate verified risk reduction
                    red = float(f.get("verified_risk_reduction", 0.0) or 0.0)
                    total_verified_reduction += red

                    # Compute remediation duration for MTTR if timestamps exist
                    f_created = f.get("created_at")
                    f_resolved = f.get("resolved_at") or f.get("updated_at")
                    if f_created and f_resolved:
                        try:
                            t_start = datetime.fromisoformat(f_created.replace("Z", "+00:00"))
                            t_end = datetime.fromisoformat(f_resolved.replace("Z", "+00:00"))
                            dur_hours = max(0.1, (t_end - t_start).total_seconds() / 3600.0)
                            all_resolved_durations_hours.append(dur_hours)
                        except Exception:
                            pass

            # Calculate calibrated risk score for this historical scan
            risk_score_obj = CyberRiskEngine.calculate_scan_risk(
                scan_id=scan_id,
                findings=findings,
            )

            history_points.append(
                AssessmentTrendPoint(
                    scan_id=scan_id,
                    timestamp=created_at,
                    risk_score=risk_score_obj.score,
                    severity_counts=sev_counts,
                    verified_remediations_count=resolved_count,
                    new_findings_count=len(findings),
                    total_findings_count=len(findings),
                )
            )

        # Also incorporate remediation tasks into MTTR if available
        tasks_cursor = db["remediation_tasks"].find({"status": "resolved"}, {"_id": 0})
        resolved_tasks = await tasks_cursor.to_list(length=100)
        for t in resolved_tasks:
            total_verified_reduction += float(t.get("verified_risk_reduction", 0.0) or 0.0)
            t_created = t.get("created_at")
            t_updated = t.get("updated_at")
            if t_created and t_updated:
                try:
                    t_start = datetime.fromisoformat(t_created.replace("Z", "+00:00"))
                    t_end = datetime.fromisoformat(t_updated.replace("Z", "+00:00"))
                    dur_hours = max(0.1, (t_end - t_start).total_seconds() / 3600.0)
                    all_resolved_durations_hours.append(dur_hours)
                except Exception:
                    pass

        # Calculate average MTTR
        mttr_hours: Optional[float] = None
        if all_resolved_durations_hours:
            mttr_hours = round(sum(all_resolved_durations_hours) / len(all_resolved_durations_hours), 1)

        # Determine overall trend direction
        trend_direction = "stable"
        if len(history_points) >= 2:
            first_score = history_points[0].risk_score
            last_score = history_points[-1].risk_score
            diff = last_score - first_score
            if diff < -5.0:
                trend_direction = "improving"
            elif diff > 5.0:
                trend_direction = "deteriorating"
            else:
                trend_direction = "stable"

        return AssessmentTrendView(
            target=target,
            history_points=history_points,
            mttr_hours_average=mttr_hours,
            total_verified_risk_reduction=round(total_verified_reduction, 1),
            posture_trend_direction=trend_direction,
            data_provenance={
                "scans_analyzed": len(history_points),
                "resolved_items_counted": len(all_resolved_durations_hours),
                "figure_origins": {
                    "history_points": FigureOrigin.OBSERVED.value,
                    "risk_scores": FigureOrigin.MODELED.value,
                    "mttr_hours": FigureOrigin.OBSERVED.value,
                    "total_verified_risk_reduction": FigureOrigin.OBSERVED.value,
                },
                "sources": ["scans", "findings", "retests", "remediation_tasks"],
                "assumptions": [
                    "Risk reduction is calculated exclusively from verified retests where retest_status == RESOLVED.",
                    "MTTR is computed from creation timestamp to verified retest resolution timestamp.",
                ],
            },
        )


trend_service = TrendService()
