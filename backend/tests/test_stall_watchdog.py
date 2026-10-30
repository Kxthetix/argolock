"""Test stall watchdog and recovery when workers terminate or stall."""
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from app.models.scan import ScanStatus, StageStatus, StageOutcome, default_stages
from app.services.pipeline_orchestrator import PipelineOrchestrator


def test_stall_watchdog_detects_killed_worker():
    """
    Test Phase 3 Gate requirement:
    Killing or losing an active worker (e.g. exploit_worker dies mid-execution)
    causes the watchdog to detect the stale heartbeat and transition the scan
    to 'failed' with an explicit stalled_reason.
    """
    scan_id = "stalled-scan-test-001"
    now = datetime.now(timezone.utc)
    stale_heartbeat = now - timedelta(seconds=120)

    raw_stages = default_stages()
    stages = {k: v.model_dump() for k, v in raw_stages.items()}
    # Recon finished successfully
    stages["recon"]["status"] = StageStatus.COMPLETED.value
    stages["recon"]["outcome"] = StageOutcome.CLEAN.value
    # Scanning finished successfully
    stages["scanning"]["status"] = StageStatus.COMPLETED.value
    stages["scanning"]["outcome"] = StageOutcome.FINDINGS_FOUND.value
    # Exploitation started, but worker was killed 2 minutes ago
    stages["exploitation"]["status"] = StageStatus.RUNNING.value
    stages["exploitation"]["started_at"] = (now - timedelta(seconds=180)).isoformat().replace("+00:00", "Z")
    stages["exploitation"]["heartbeat_at"] = stale_heartbeat

    scan_doc = {
        "id": scan_id,
        "status": ScanStatus.RUNNING.value,
        "current_phase": "Exploitation Stage 2/6: Cross-Site Scripting (XSS)",
        "progress_percent": 69,
        "stages": stages,
        "heartbeat_at": stale_heartbeat,
    }

    mock_scans = MagicMock()
    mock_db = {"scans": mock_scans}
    mock_scans.find.return_value = [scan_doc]

    orchestrator = PipelineOrchestrator(db_getter=lambda: mock_db)

    # Run stall recovery with a 30-second timeout
    stalled_scans = orchestrator.check_and_recover_stalled_scans(stall_timeout_seconds=30.0, db=mock_db)

    assert len(stalled_scans) == 1
    assert stalled_scans[0]["scan_id"] == scan_id
    assert "exploitation worker died or stopped emitting heartbeats" in stalled_scans[0]["reason"]

    # Verify database update to failed with stalled reason
    update_calls = mock_scans.update_one.call_args_list
    assert len(update_calls) >= 1
    _, update_kwargs = update_calls[0]
    set_fields = update_calls[0][0][1]["$set"]

    assert set_fields["status"] == ScanStatus.FAILED.value
    assert "died or stopped emitting heartbeats" in set_fields["stalled_reason"]
    assert set_fields["stages.exploitation.status"] == StageStatus.FAILED.value
    assert set_fields["stages.exploitation.outcome"] == StageOutcome.ERROR.value


def test_stall_watchdog_ignores_healthy_active_worker():
    """Watchdog does not fail scans whose workers are emitting fresh heartbeats."""
    scan_id = "healthy-scan-test-002"
    now = datetime.now(timezone.utc)
    fresh_heartbeat = now - timedelta(seconds=5)

    raw_stages = default_stages()
    stages = {k: v.model_dump() for k, v in raw_stages.items()}
    stages["recon"]["status"] = StageStatus.COMPLETED.value
    stages["scanning"]["status"] = StageStatus.RUNNING.value
    stages["scanning"]["heartbeat_at"] = fresh_heartbeat

    scan_doc = {
        "id": scan_id,
        "status": ScanStatus.RUNNING.value,
        "current_phase": "Vulnerability Scanning",
        "progress_percent": 45,
        "stages": stages,
        "heartbeat_at": fresh_heartbeat,
    }

    mock_scans = MagicMock()
    mock_db = {"scans": mock_scans}
    mock_scans.find.return_value = [scan_doc]

    orchestrator = PipelineOrchestrator(db_getter=lambda: mock_db)
    stalled_scans = orchestrator.check_and_recover_stalled_scans(stall_timeout_seconds=30.0, db=mock_db)

    assert len(stalled_scans) == 0
    mock_scans.update_one.assert_not_called()
