"""Stage-Record Orchestrator with Heartbeats, Stall Watchdog, and Cancellation for ARGOLOCK NET."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger

from app.models.scan import ScanStatus, StageStatus, StageOutcome, StageRecord


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ScanCancelledException(Exception):
    """Raised when an active scan has been cancelled by operator."""
    pass


class PipelineOrchestrator:
    """
    Manages stage lifecycle, heartbeat emission, stall detection,
    per-stage status, and safe transitions across Celery workers.
    """

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self, db: Any = None):
        if db is not None:
            return db
        if self._db_getter:
            return self._db_getter()
        try:
            from workers.recon_worker import _get_db_sync
            return _get_db_sync()
        except Exception:
            try:
                from app.database import get_db
                return get_db()
            except Exception:
                return None

    def check_cancellation(self, scan_id: str, db: Any = None) -> bool:
        """Return True if scan has been cancelled; raise ScanCancelledException if check fails closed."""
        db = self._get_db(db)
        if db is None:
            return False
        doc = db["scans"].find_one({"id": scan_id}, {"status": 1})
        if doc and doc.get("status") == ScanStatus.CANCELLED.value:
            logger.warning(f"Scan {scan_id} is CANCELLED. Halting pipeline execution.")
            return True
        return False

    def record_stage_start(
        self,
        scan_id: str,
        stage_key: str,
        stage_name: str,
        progress_percent: int,
        db: Any = None,
    ):
        """Record the beginning of a pipeline stage and start heartbeats."""
        if self.check_cancellation(scan_id, db=db):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled before stage '{stage_name}'.")

        db = self._get_db(db)
        if db is None:
            return
        now = utc_now()
        now_str = utc_now_iso()

        db["scans"].update_one(
            {"id": scan_id},
            {
                "$set": {
                    "status": ScanStatus.RUNNING.value,
                    "current_phase": stage_name,
                    "progress_percent": progress_percent,
                    "started_at": now_str,
                    "heartbeat_at": now,
                    f"stages.{stage_key}.status": StageStatus.RUNNING.value,
                    f"stages.{stage_key}.started_at": now,
                    f"stages.{stage_key}.heartbeat_at": now,
                }
            }
        )
        logger.info(f"[{scan_id}] Stage '{stage_name}' started ({progress_percent}%)")

    def record_heartbeat(self, scan_id: str, stage_key: str, db: Any = None):
        """Emit periodic heartbeat for the current active stage."""
        db = self._get_db(db)
        if db is None:
            return
        now = utc_now()
        db["scans"].update_one(
            {"id": scan_id},
            {
                "$set": {
                    "heartbeat_at": now,
                    f"stages.{stage_key}.heartbeat_at": now,
                }
            }
        )

    def record_stage_completion(
        self,
        scan_id: str,
        stage_key: str,
        outcome: StageOutcome,
        summary: str = "",
        findings_count: int = 0,
        tools_executed: Optional[List[str]] = None,
        error: Optional[str] = None,
        db: Any = None,
    ) -> StageStatus:
        """
        Record stage completion.
        CRITICAL RULE: A stage with no usable output cannot be SUCCESS/COMPLETED.
        - UNREACHABLE -> PARTIALLY_COMPLETED
        - BLOCKED -> PARTIALLY_COMPLETED
        - SCANNED_WITH_NO_FINDINGS -> COMPLETED
        - FINDINGS_FOUND -> COMPLETED
        - PARTIAL -> PARTIALLY_COMPLETED
        - ERROR -> FAILED
        """
        db = self._get_db(db)
        if db is None:
            return StageStatus.COMPLETED
        now = utc_now()

        # Enforce no-usable-output rule
        if outcome in (StageOutcome.UNREACHABLE, StageOutcome.BLOCKED, StageOutcome.PARTIAL):
            stage_status = StageStatus.PARTIALLY_COMPLETED
        elif outcome == StageOutcome.ERROR:
            stage_status = StageStatus.FAILED
        else:
            stage_status = StageStatus.COMPLETED

        update_fields = {
            f"stages.{stage_key}.status": stage_status.value,
            f"stages.{stage_key}.outcome": outcome.value,
            f"stages.{stage_key}.completed_at": now,
            f"stages.{stage_key}.heartbeat_at": now,
            f"stages.{stage_key}.summary": summary,
            f"stages.{stage_key}.findings_count": findings_count,
            f"stages.{stage_key}.tools_executed": tools_executed or [],
        }
        if error:
            update_fields[f"stages.{stage_key}.error"] = error

        # Propagate reachability status to scan document if discovered
        if outcome == StageOutcome.UNREACHABLE:
            update_fields["target_reachable"] = False
            update_fields["coverage"] = "none"
            update_fields["coverage_summary"] = "none"
        elif stage_key == "recon" and outcome in (StageOutcome.CLEAN, StageOutcome.PARTIAL, StageOutcome.FINDINGS_FOUND):
            update_fields["target_reachable"] = True

        db["scans"].update_one({"id": scan_id}, {"$set": update_fields})
        logger.info(f"[{scan_id}] Stage '{stage_key}' finished: status={stage_status.value}, outcome={outcome.value}")
        return stage_status

    def record_stage_skipped(self, scan_id: str, stage_key: str, reason: str = "", db: Any = None):
        """Record a stage that was intentionally skipped (e.g. exploitation disabled)."""
        db = self._get_db(db)
        if db is None:
            return
        now = utc_now()
        db["scans"].update_one(
            {"id": scan_id},
            {
                "$set": {
                    f"stages.{stage_key}.status": StageStatus.SKIPPED.value,
                    f"stages.{stage_key}.outcome": StageOutcome.CLEAN.value,
                    f"stages.{stage_key}.completed_at": now,
                    f"stages.{stage_key}.summary": reason or "Stage skipped by configuration",
                }
            }
        )
        logger.info(f"[{scan_id}] Stage '{stage_key}' marked as skipped: {reason}")

    def evaluate_scan_final_status(self, scan_id: str, db: Any = None) -> ScanStatus:
        """Calculate the overall scan status based on all constituent stage outcomes."""
        db = self._get_db(db)
        if db is None:
            return ScanStatus.FAILED
        doc = db["scans"].find_one({"id": scan_id})
        if not doc:
            return ScanStatus.FAILED

        if doc.get("status") == ScanStatus.CANCELLED.value:
            return ScanStatus.CANCELLED

        stages = doc.get("stages", {})
        has_failure = any(
            (getattr(s, "status", None) == StageStatus.FAILED.value) or (isinstance(s, dict) and s.get("status") == StageStatus.FAILED.value)
            for s in stages.values()
        )
        if has_failure:
            return ScanStatus.FAILED

        target_unreachable = doc.get("target_reachable") is False or any(
            (getattr(s, "outcome", None) == StageOutcome.UNREACHABLE.value) or (isinstance(s, dict) and s.get("outcome") == StageOutcome.UNREACHABLE.value)
            for s in stages.values()
        )
        has_partial = any(
            ((getattr(s, "status", None) == StageStatus.PARTIALLY_COMPLETED.value) or (isinstance(s, dict) and s.get("status") == StageStatus.PARTIALLY_COMPLETED.value))
            or ((getattr(s, "outcome", None) in (StageOutcome.PARTIAL.value, StageOutcome.BLOCKED.value)) or (isinstance(s, dict) and s.get("outcome") in (StageOutcome.PARTIAL.value, StageOutcome.BLOCKED.value)))
            for s in stages.values()
        )

        if target_unreachable or has_partial:
            return ScanStatus.PARTIALLY_COMPLETED

        return ScanStatus.COMPLETED

    def check_and_recover_stalled_scans(self, stall_timeout_seconds: float = 60.0, db: Any = None) -> List[Dict[str, Any]]:
        """
        Watchdog: detects scans whose active worker died or stopped emitting heartbeats.
        If an active stage heartbeat has timed out, fails/stalls the scan with an explicit reason.
        """
        db = self._get_db(db)
        if db is None:
            return []
        now = utc_now()
        cutoff = now - timedelta(seconds=stall_timeout_seconds)

        # Scans currently in running or queued state
        active_scans = list(db["scans"].find({
            "status": {"$in": [ScanStatus.RUNNING.value, ScanStatus.QUEUED.value, "pending", "recon", "scanning", "exploiting", "ai_analysis"]}
        }))

        recovered = []
        for scan in active_scans:
            scan_id = scan["id"]
            stages = scan.get("stages", {})
            current_phase = scan.get("current_phase", "Unknown")

            # Identify the currently active stage
            active_stage_key = None
            active_stage_record = None
            for k, stg in stages.items():
                stg_status = getattr(stg, "status", None) or (stg.get("status") if isinstance(stg, dict) else None)
                if hasattr(stg_status, "value"):
                    stg_status = stg_status.value
                if stg_status == StageStatus.RUNNING.value:
                    active_stage_key = k
                    active_stage_record = stg
                    break

            if not active_stage_key:
                # If no stage marked running, check if scan was stuck in exploiting or scanning
                if scan.get("status") in ("exploiting", "scanning", "recon") or "Exploitation" in current_phase:
                    active_stage_key = "exploitation" if "Exploit" in current_phase else "scanning"

            # Check heartbeat
            hb = None
            if active_stage_record:
                hb = getattr(active_stage_record, "heartbeat_at", None) or (
                    active_stage_record.get("heartbeat_at") if isinstance(active_stage_record, dict) else None
                )
            if not hb and scan.get("heartbeat_at"):
                hb = scan["heartbeat_at"]
            elif not hb and scan.get("started_at"):
                try:
                    hb = datetime.fromisoformat(scan["started_at"].replace("Z", "+00:00"))
                except Exception:
                    hb = None

            is_stalled = False
            if hb:
                if hb.tzinfo is None:
                    hb = hb.replace(tzinfo=timezone.utc)
                if hb < cutoff:
                    is_stalled = True
            else:
                # No heartbeat recorded and created earlier than cutoff
                created_at = scan.get("created_at")
                if isinstance(created_at, datetime):
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)
                    if created_at < cutoff:
                        is_stalled = True

            if is_stalled:
                reason = (
                    f"Stalled: {active_stage_key or 'pipeline'} worker died or stopped emitting heartbeats "
                    f"(timeout > {int(stall_timeout_seconds)}s)"
                )
                now_str = utc_now_iso()
                update_set = {
                    "status": ScanStatus.FAILED.value,
                    "error": reason,
                    "stalled_reason": reason,
                    "current_phase": f"Stalled ({active_stage_key or 'worker'})",
                    "completed_at": now_str,
                }
                if active_stage_key:
                    update_set[f"stages.{active_stage_key}.status"] = StageStatus.FAILED.value
                    update_set[f"stages.{active_stage_key}.outcome"] = StageOutcome.ERROR.value
                    update_set[f"stages.{active_stage_key}.error"] = reason
                    update_set[f"stages.{active_stage_key}.completed_at"] = now

                db["scans"].update_one({"id": scan_id}, {"$set": update_set})
                logger.error(f"[StallWatchdog] Recovered stalled scan {scan_id}: {reason}")
                recovered.append({"scan_id": scan_id, "reason": reason, "stage": active_stage_key})

        return recovered


orchestrator = PipelineOrchestrator()
