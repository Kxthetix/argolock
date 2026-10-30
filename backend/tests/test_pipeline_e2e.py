"""
End-to-end integration tests for the Celery tasks pipeline.
Executes the tasks sequentially as python functions to verify DB updates and robustness.
"""
from __future__ import annotations

# pyrefly: ignore [missing-import]
import pytest
import uuid
from datetime import datetime, timezone

from unittest.mock import patch
from app.config import settings
from app.database import get_db
from workers.recon_worker import run_recon, _get_db_sync
from workers.scanner_worker import run_scanner
from workers.exploit_worker import run_exploit
from workers.ai_worker import run_ai_analysis
from agents.report_agent import ReportAgent


class MockProvider:
    async def complete(self, *args, **kwargs):
        return "[]"
    async def complete_with_retry(self, *args, **kwargs):
        return "[]"
    async def complete_json(self, *args, **kwargs):
        return []


def test_pipeline_e2e_execution():
    """Test full pipeline execution from recon to scanning, exploitation, and AI analysis."""
    db_sync = _get_db_sync()
    scan_id = str(uuid.uuid4())
    
    # 1. Create a dummy scan document in MongoDB
    scan_doc = {
        "id": scan_id,
        "name": f"E2E Test Scan {scan_id}",
        "scope": {
            "target": "scanme.nmap.org",
            "authorized": True,
            "max_depth": 1
        },
        "config": {
            "safe_mode": True,
            "enable_exploitation": False,
            "nuclei_severity": ["info"]
        },
        "status": "pending",
        "current_phase": "Pending",
        "progress_percent": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    db_sync["scans"].insert_one(scan_doc)
    
    mock_prov = MockProvider()
    with patch("ai_providers.get_provider", return_value=mock_prov), \
         patch.object(ReportAgent, "_generate_executive_summary", return_value="Assessment complete."), \
         patch("agents.report_agent.generate_pdf", return_value="/tmp/test_report.pdf"):

        # 2. Run run_recon synchronously
        recon_results = run_recon(scan_id, scan_doc)
        assert recon_results is not None
        assert recon_results["target"] == "scanme.nmap.org"
        
        # Verify DB state after recon / eager execution
        scan_after_recon = db_sync["scans"].find_one({"id": scan_id})
        assert scan_after_recon["status"] in ("recon", "running", "completed", "partially_completed")
        
        # 3. If not already eager completed, run scanner and downstream tasks
        if scan_after_recon["status"] not in ("completed", "partially_completed"):
            scanner_results = run_scanner(recon_results, scan_id)
            assert scanner_results is not None
            assert scanner_results["target"] == "scanme.nmap.org"
            
            exploit_results = run_exploit(scanner_results, scan_id)
            assert exploit_results is not None
            
            run_ai_analysis(exploit_results, scan_id)
            
        # Verify DB state after completion
        scan_after_ai = db_sync["scans"].find_one({"id": scan_id})
        assert scan_after_ai["status"] in ("completed", "partially_completed")
        assert scan_after_ai["progress_percent"] == 100


def test_celery_chain_e2e():
    """Test the Celery chain execution using eager mode to verify argument routing."""
    from workers.celery_app import celery_app, run_full_pipeline
    
    # Enable eager mode for this test
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    
    db_sync = _get_db_sync()
    scan_id = str(uuid.uuid4())
    
    scan_doc = {
        "id": scan_id,
        "name": f"Chain E2E Test Scan {scan_id}",
        "scope": {
            "target": "scanme.nmap.org",
            "authorized": True,
            "max_depth": 1
        },
        "config": {
            "safe_mode": True,
            "enable_exploitation": False,
            "nuclei_severity": ["info"]
        },
        "status": "pending",
        "current_phase": "Pending",
        "progress_percent": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    db_sync["scans"].insert_one(scan_doc)
    
    mock_prov = MockProvider()
    with patch("ai_providers.get_provider", return_value=mock_prov), \
         patch.object(ReportAgent, "_generate_executive_summary", return_value="Assessment complete."), \
         patch("agents.report_agent.generate_pdf", return_value="/tmp/test_report.pdf"):

        # Trigger the chain
        scan_doc.pop("_id", None)
        run_full_pipeline(scan_id, scan_doc)
        
        # Check if the scan completed successfully in DB
        scan_after_chain = db_sync["scans"].find_one({"id": scan_id})
        assert scan_after_chain["status"] in ("completed", "partially_completed", "running")
