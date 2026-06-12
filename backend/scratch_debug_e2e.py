import os
import sys
import uuid
from datetime import datetime
from pymongo import MongoClient

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.config import settings
settings.mongodb_db = "argolock_test"

from app.database import connect_db, get_db
from workers.recon_worker import run_recon, _get_db_sync
from workers.scanner_worker import run_scanner
from workers.exploit_worker import run_exploit
from workers.ai_worker import run_ai_analysis
from workers.celery_app import run_async

async def main():
    await connect_db()
    db = get_db()
    scan_id = str(uuid.uuid4())
    
    scan_doc = {
        "id": scan_id,
        "name": f"Debug Test Scan {scan_id}",
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
    db_sync = _get_db_sync()
    
    print("Initial check:", db_sync["scans"].find_one({"id": scan_id}) is not None)
    
    # 1. Recon
    recon_results = run_recon(scan_id, scan_doc)
    print("After recon check:", db_sync["scans"].find_one({"id": scan_id}) is not None)
    
    # 2. Scanner
    # Limit tools to run faster in debug
    scanner_results = run_scanner(recon_results, scan_id)
    print("After scanner check:", db_sync["scans"].find_one({"id": scan_id}) is not None)
    
    # 3. Exploit
    exploit_results = run_exploit(scanner_results, scan_id)
    print("After exploit check:", db_sync["scans"].find_one({"id": scan_id}) is not None)
    
    # 4. AI Analysis
    run_ai_analysis(exploit_results, scan_id)
    scan_doc_final = db_sync["scans"].find_one({"id": scan_id})
    print("After AI check:", scan_doc_final is not None)
    if scan_doc_final:
        print("Final status:", scan_doc_final.get("status"))
        print("Final error:", scan_doc_final.get("error"))

if __name__ == "__main__":
    run_async(main())
