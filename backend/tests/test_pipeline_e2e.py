"""
End-to-end integration tests for the Celery tasks pipeline.
Executes the tasks sequentially as python functions to verify DB updates and robustness.
"""
from __future__ import annotations

import pytest
import uuid
from datetime import datetime

from app.config import settings
from app.database import get_db
from workers.recon_worker import run_recon, _get_db_sync
from workers.scanner_worker import run_scanner
from workers.exploit_worker import run_exploit
from workers.ai_worker import run_ai_analysis


@pytest.mark.asyncio
async def test_pipeline_e2e_execution(client):
    """Test full pipeline execution from recon to scanning, exploitation, and AI analysis."""
    db = get_db()
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
        "created_at": datetime.utcnow().isoformat(),
    }
    await db["scans"].insert_one(scan_doc)
    
    # 2. Run run_recon synchronously
    # We pass the scan_data directly
    recon_results = run_recon(scan_id, scan_doc)
    assert recon_results is not None
    assert recon_results["target"] == "scanme.nmap.org"
    
    # Verify DB state after recon
    db_sync = _get_db_sync()
    scan_after_recon = db_sync["scans"].find_one({"id": scan_id})
    assert scan_after_recon["status"] == "recon"
    assert scan_after_recon["current_phase"] == "Recon Complete"
    assert scan_after_recon["progress_percent"] == 30
    
    # 3. Run run_scanner synchronously
    scanner_results = run_scanner(recon_results, scan_id)
    assert scanner_results is not None
    assert scanner_results["target"] == "scanme.nmap.org"
    
    # Verify DB state after scanning
    scan_after_scanner = db_sync["scans"].find_one({"id": scan_id})
    assert scan_after_scanner["status"] == "scanning"
    assert scan_after_scanner["current_phase"] == "Scanner Complete"
    assert scan_after_scanner["progress_percent"] == 70
    
    # 4. Run run_exploit synchronously
    # Since enable_exploitation is False, it should skip exploitation phase and return scanner_results
    exploit_results = run_exploit(scanner_results, scan_id)
    assert exploit_results is not None
    
    # AI Analysis should run and complete successfully because it catches agent failures (like Ollama offline) cleanly
    run_ai_analysis(exploit_results, scan_id)
        
    # Verify DB state after completion
    scan_after_ai = db_sync["scans"].find_one({"id": scan_id})
    assert scan_after_ai["status"] == "completed"
    assert scan_after_ai["progress_percent"] == 100


@pytest.mark.asyncio
async def test_celery_chain_e2e(client):
    """Test the Celery chain execution using eager mode to verify argument routing."""
    from workers.celery_app import celery_app, run_full_pipeline
    
    # Enable eager mode for this test
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    
    db = get_db()
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
        "created_at": datetime.utcnow().isoformat(),
    }
    await db["scans"].insert_one(scan_doc)
    
    # Trigger the chain
    run_full_pipeline(scan_id, scan_doc)
    
    # Check if the scan completed successfully in DB
    db_sync = _get_db_sync()
    scan_after_chain = db_sync["scans"].find_one({"id": scan_id})
    assert scan_after_chain["status"] == "completed"
    assert scan_after_chain["progress_percent"] == 100
