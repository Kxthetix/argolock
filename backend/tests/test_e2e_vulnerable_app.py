"""
End-to-End CI test against a local vulnerable application (Juice Shop / DVWA style).

Tests:
1. Full end-to-end pipeline against a running local vulnerable target reaches reporting,
   identifies real vulnerabilities (missing CSP, reflected XSS, exposed secrets),
   and produces an executive report.
2. Phase 3 Gate: If the exploit worker is killed or crashes mid-execution,
   the stall watchdog detects the dead worker and marks the scan as failed
   with an explicit stall reason.
"""
from __future__ import annotations

import http.server
import socket
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
import httpx

from app.models.scan import ScanStatus, StageStatus, StageOutcome, default_stages
from app.services.pipeline_orchestrator import PipelineOrchestrator
from agents.report_agent import ReportAgent
from workers.recon_worker import run_recon
from workers.scanner_worker import run_scanner
from workers.exploit_worker import run_exploit
from workers.ai_worker import run_ai_analysis


class VulnerableAppHandler(http.server.BaseHTTPRequestHandler):
    """
    Lightweight local vulnerable web app mimicking OWASP Juice Shop / DVWA endpoints:
    - Missing Content-Security-Policy (CSP)
    - Reflected XSS on /search and /rest/products/search
    - Sensitive information exposure on /.env
    """
    def log_message(self, format, *args):
        # Suppress noisy HTTP request logging during test execution
        pass

    def do_GET(self):
        url_path = self.path

        if url_path.startswith("/search") or url_path.startswith("/rest/products/search"):
            # Reflected XSS vulnerability: unescaped parameter reflection
            query = url_path.split("q=")[-1] if "q=" in url_path else "test"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # Deliberately omit Content-Security-Policy and X-Frame-Options
            self.end_headers()
            response_body = f"<html><body><h1>Search Results</h1><p>Query: {query}</p></body></html>"
            self.wfile.write(response_body.encode("utf-8"))

        elif url_path == "/.env":
            # Information disclosure vulnerability
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            secrets = "DB_HOST=127.0.0.1\nDB_PASSWORD=supersecret_argolock_live_key_9981\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n"
            self.wfile.write(secrets.encode("utf-8"))

        elif url_path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")

        else:
            # Default index page without security headers
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Vulnerable App</title></head><body><h1>Welcome</h1></body></html>")


@pytest.fixture(scope="module")
def vulnerable_server():
    """Start local vulnerable web server on a free port in a background daemon thread."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), VulnerableAppHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Wait for server readiness
    target_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            r = httpx.get(target_url, timeout=0.5)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.05)

    yield f"127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


def test_e2e_pipeline_reaches_reporting_on_vulnerable_app(vulnerable_server):
    """
    E2E CI Test: Full pipeline against local vulnerable application.
    Verifies that:
    1. Pipeline starts with queued status.
    2. Recon detects target as reachable.
    3. Scanners and exploit worker detect real vulnerabilities (CSP missing, XSS, exposed .env).
    4. AI pipeline processes findings and reaches reporting stage.
    5. Final scan status is completed (or partially_completed) with findings > 0.
    """
    scan_id = "e2e-vulnerable-scan-001"
    target = vulnerable_server
    initial_stages = {k: v.model_dump() for k, v in default_stages().items()}

    scan_doc = {
        "id": scan_id,
        "scope": {"target": target, "authorized": True},
        "config": {"enable_exploitation": True, "ai_scoring": True},
        "status": ScanStatus.QUEUED.value,
        "current_phase": "Queued",
        "progress_percent": 0,
        "stages": initial_stages,
        "tool_results": {},
        "target_reachable": None,
    }

    persisted_raw_findings = []
    persisted_findings = []
    persisted_reports = []

    def mock_update_one(filter_dict, update_dict):
        if "$set" in update_dict:
            for k, v in update_dict["$set"].items():
                if "." in k:
                    parts = k.split(".")
                    sub = scan_doc
                    for p in parts[:-1]:
                        if p not in sub:
                            sub[p] = {}
                        sub = sub[p]
                    sub[parts[-1]] = v
                else:
                    scan_doc[k] = v

    def mock_insert_raw(items):
        persisted_raw_findings.extend(items)

    mock_scans = MagicMock()
    mock_scans.find_one.side_effect = lambda query, *args, **kwargs: scan_doc if query.get("id") == scan_id else None
    mock_scans.update_one.side_effect = mock_update_one

    mock_raw_findings = MagicMock()
    mock_raw_findings.find.side_effect = lambda query, *args, **kwargs: [f for f in persisted_raw_findings if f.get("scan_id") == scan_id]
    mock_raw_findings.insert_many.side_effect = mock_insert_raw

    mock_findings = MagicMock()
    mock_findings.insert_many.side_effect = lambda items: persisted_findings.extend(items)

    mock_reports = MagicMock()
    mock_reports.find_one.return_value = None
    mock_reports.insert_one.side_effect = lambda rep: persisted_reports.append(rep)

    mock_vapt_audit = MagicMock()
    mock_vapt_audit.find_one.return_value = None

    cols = {
        "scans": mock_scans,
        "raw_findings": mock_raw_findings,
        "findings": mock_findings,
        "reports": mock_reports,
        "approvals": MagicMock(),
        "audit_logs": MagicMock(),
        "vapt_audit_logs": mock_vapt_audit,
    }
    mock_db = MagicMock()
    mock_db.__getitem__.side_effect = lambda k: cols.get(k, MagicMock())

    class MockProvider:
        async def complete(self, *args, **kwargs):
            return "[]"
        async def complete_with_retry(self, *args, **kwargs):
            return "[]"
        async def complete_json(self, *args, **kwargs):
            return []

    mock_prov = MockProvider()

    # Execute Pipeline: Recon -> Scanner -> Exploit -> AI Analysis / Reporting
    with patch("workers.recon_worker._get_db_sync", return_value=mock_db), \
         patch("workers.scanner_worker._get_db_sync", return_value=mock_db), \
         patch("workers.exploit_worker._get_db_sync", return_value=mock_db), \
         patch("workers.ai_worker._get_db_sync", return_value=mock_db), \
         patch("ai_providers.get_provider", return_value=mock_prov), \
         patch("workers.recon_worker._broadcast"), \
         patch("workers.scanner_worker._broadcast"), \
         patch("workers.exploit_worker._broadcast"), \
         patch("workers.ai_worker._broadcast"), \
         patch("workers.scanner_worker.run_scanner.delay") as mock_scanner_delay, \
         patch("workers.exploit_worker.run_exploit.delay") as mock_exploit_delay, \
         patch("workers.ai_worker.run_ai_analysis.delay") as mock_ai_delay, \
         patch.object(ReportAgent, "_generate_executive_summary", return_value="Assessment summary of vulnerable application."), \
         patch("agents.report_agent.generate_pdf", return_value="/tmp/test_report.pdf"):

        # 1. Recon stage
        recon_result = run_recon(scan_id, scan_doc)
        assert recon_result["status"] == "success"
        assert scan_doc.get("target_reachable") is True
        assert scan_doc["stages"]["recon"]["status"] in (StageStatus.COMPLETED.value, StageStatus.PARTIALLY_COMPLETED.value)

        # 2. Scanner stage
        scanner_result = run_scanner(scan_id)
        assert scanner_result["status"] == "success"
        assert scan_doc["stages"]["scanning"]["status"] in (StageStatus.COMPLETED.value, StageStatus.PARTIALLY_COMPLETED.value)

        # 3. Exploit stage against live vulnerable server
        exploit_result = run_exploit(scan_id)
        assert exploit_result["status"] == "success"
        assert scan_doc["stages"]["exploitation"]["status"] == StageStatus.COMPLETED.value
        # Real findings found from local vulnerable app
        assert len(persisted_raw_findings) > 0
        titles = [f.get("title", "") for f in persisted_raw_findings]
        # Verified that missing CSP or secret was captured from the live server
        assert any("Content Security Policy" in t or "Secret" in t or "Shannon" in t for t in titles)

        # 4. AI & Reporting stage
        run_ai_analysis(scan_id)

        # 5. Pipeline completion & reporting assertions
        assert scan_doc["stages"]["ai_analysis"]["status"] == StageStatus.COMPLETED.value
        assert scan_doc["stages"]["reporting"]["status"] == StageStatus.COMPLETED.value
        assert scan_doc["status"] in (ScanStatus.COMPLETED.value, ScanStatus.PARTIALLY_COMPLETED.value)
        assert scan_doc["progress_percent"] == 100
        assert len(persisted_reports) >= 1
        assert persisted_reports[0]["scan_id"] == scan_id


def test_e2e_gate_exploit_worker_killed_results_in_failed_stalled():
    """
    Phase 3 Gate Assertion:
    When an active exploit worker process is killed/terminated midway,
    the pipeline transitions the scan to 'failed' with an explicit stalled_reason.
    """
    scan_id = "killed-exploit-worker-scan-002"
    now = datetime.now(timezone.utc)
    stale_heartbeat = now - timedelta(seconds=90)

    stages = {k: v.model_dump() for k, v in default_stages().items()}
    stages["recon"]["status"] = StageStatus.COMPLETED.value
    stages["scanning"]["status"] = StageStatus.COMPLETED.value
    # Exploit worker was running but process was killed 90 seconds ago
    stages["exploitation"]["status"] = StageStatus.RUNNING.value
    stages["exploitation"]["heartbeat_at"] = stale_heartbeat

    scan_doc = {
        "id": scan_id,
        "status": ScanStatus.RUNNING.value,
        "current_phase": "Exploitation Stage 1/6: Web Application Exploits",
        "progress_percent": 68,
        "stages": stages,
        "heartbeat_at": stale_heartbeat,
    }

    mock_scans = MagicMock()
    mock_db = {"scans": mock_scans}
    mock_scans.find.return_value = [scan_doc]

    orchestrator = PipelineOrchestrator(db_getter=lambda: mock_db)

    # Watchdog runs with a 30-second timeout threshold
    stalled = orchestrator.check_and_recover_stalled_scans(stall_timeout_seconds=30.0, db=mock_db)

    assert len(stalled) == 1
    assert stalled[0]["scan_id"] == scan_id
    assert "exploitation worker died or stopped emitting heartbeats" in stalled[0]["reason"]

    # Verify that database update transitioned status to 'failed' with stall reason
    update_calls = mock_scans.update_one.call_args_list
    assert len(update_calls) >= 1
    set_fields = update_calls[0][0][1]["$set"]
    assert set_fields["status"] == ScanStatus.FAILED.value
    assert "died or stopped emitting heartbeats" in set_fields["stalled_reason"]
