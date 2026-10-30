"""Golden test: scanning an unreachable target yields zero findings and coverage stated as none."""
import asyncio
from unittest.mock import MagicMock, patch
import pytest

from app.models.scan import ScanDocument, ScanScope, ScanConfig
from workers.ai_worker import run_ai_analysis
from agents.report_agent import ReportAgent


def test_golden_unreachable_target_pipeline():
    """
    Golden Test on an unreachable target:
    - Target: '192.0.2.1' (RFC 5737 TEST-NET-1, guaranteed unreachable blackhole)
    - Reconn & scanning return no open ports, no live HTTP endpoints.
    - Assert that:
      1. finding_count is 0.
      2. No findings are persisted or reported.
      3. Coverage is stated as 'none'.
      4. Target is marked target_reachable = False.
      5. The generated report reflects zero findings and 'none' coverage.
    """
    scan_id = "golden-unreachable-scan-001"
    target = "192.0.2.1"

    # Scan doc reflecting an unreachable target with empty recon results
    scan_doc = {
        "id": scan_id,
        "scope": {"target": target, "authorized": True},
        "config": {"enable_exploitation": True, "ai_scoring": True},
        "status": "exploiting",
        "tool_results": {
            "nmap": {
                "tool": "socket-fallback",
                "parsed_data": {"open_ports": [], "hosts": [], "vulnerabilities": []},
            },
            "httpx_probe": {
                "tool": "httpx_probe",
                "parsed_data": {"live_count": 0, "probes": []},
            },
            "whatweb": {
                "tool": "whatweb",
                "parsed_data": {"technologies": []},
            }
        }
    }

    mock_scans = MagicMock()
    mock_findings = MagicMock()
    mock_raw_findings = MagicMock()
    mock_reports = MagicMock()

    cols = {
        "scans": mock_scans,
        "findings": mock_findings,
        "raw_findings": mock_raw_findings,
        "reports": mock_reports,
    }
    mock_db = MagicMock()
    mock_db.__getitem__.side_effect = lambda k: cols.get(k, MagicMock())

    # Raw findings: empty because target was unreachable
    mock_scans.find_one.return_value = scan_doc
    mock_raw_findings.find.return_value = []
    mock_reports.find_one.return_value = None

    with patch("workers.ai_worker._get_db_sync", return_value=mock_db), \
         patch("workers.ai_worker._broadcast"), \
         patch.object(ReportAgent, "_generate_executive_summary", return_value="Assessment complete."), \
         patch("agents.report_agent.generate_pdf", return_value="/tmp/test_report.pdf"):

        run_ai_analysis(scan_id)

    # 1. Pipeline updated scan status to completed or partially_completed (unreachable)
    scan_updates = {}
    for call in mock_scans.update_one.call_args_list:
        args, kwargs = call
        if "$set" in args[1]:
            scan_updates.update(args[1]["$set"])

    assert scan_updates.get("status") in ("completed", "partially_completed")

    # 2. Findings collection must have received zero insertions
    assert mock_findings.insert_many.call_count == 0

    # 3. Zero findings verified
    assert scan_updates.get("finding_count") == 0
    assert scan_updates.get("critical_count") == 0
    assert scan_updates.get("high_count") == 0
    assert scan_updates.get("medium_count") == 0
    assert scan_updates.get("low_count") == 0
    assert scan_updates.get("info_count") == 0

    # 4. Coverage stated as 'none' and target marked unreachable
    assert scan_updates.get("coverage") == "none"
    assert scan_updates.get("coverage_summary") == "none"
    assert scan_updates.get("target_reachable") is False

    # 5. Verify inserted report data
    assert mock_reports.insert_one.call_count == 1
    inserted_report = mock_reports.insert_one.call_args[0][0]
    assert inserted_report["coverage"] == "none"
    assert inserted_report["coverage_summary"] == "none"
    assert inserted_report["total_findings"] == 0
    assert len(inserted_report["findings"]) == 0
