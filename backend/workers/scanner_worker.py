"""Scanner worker — runs Nuclei, Nikto, Dalfox, OWASP ZAP."""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict

from loguru import logger

import os
import sys

# Ensure the backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.models.scan import StageOutcome, StageStatus, ScanStatus
from app.services.pipeline_orchestrator import orchestrator, ScanCancelledException
from workers.celery_app import celery_app
from workers.recon_worker import _get_db_sync, _update_scan_status, _log, _save_tool_result, _broadcast
from tools.nuclei_tool import NucleiTool
from tools.nikto_tool import NiktoTool
from tools.dalfox_tool import DalfoxTool
from tools.zap_tool import ZAPTool


import copy

def _store_raw_findings(db, scan_id: str, tool: str, findings: list):
    """Store raw tool findings as pre-processed finding documents."""
    if not findings:
        return
    # Deep copy to prevent PyMongo from mutating the original dictionaries with ObjectId
    copied_findings = copy.deepcopy(findings)
    for f in copied_findings:
        f["scan_id"] = scan_id
        f["tool_source"] = tool
        f["raw"] = True
    db["raw_findings"].insert_many(copied_findings)


@celery_app.task(name="workers.scanner_worker.run_scanner", bind=True)
def run_scanner(self, recon_results_or_scan_id: Any, scan_id: str | None = None):
    """Run all vulnerability scanners against the target."""
    if scan_id is None:
        scan_id = recon_results_or_scan_id
        recon_results = None
    else:
        recon_results = recon_results_or_scan_id

    db = _get_db_sync()
    try:
        if orchestrator.check_cancellation(scan_id, db=db):
            _log(scan_id, "warning", "Scan was cancelled before vulnerability scanning.")
            return {"status": "cancelled", "scan_id": scan_id}

        scan_doc = db["scans"].find_one({"id": scan_id})
        if not scan_doc:
            logger.error(f"Scan {scan_id} not found")
            return {}

        target = scan_doc["scope"]["target"]
        http_target = target if target.startswith("http") else f"http://{target}"
        config = scan_doc.get("config", {})
        severities = config.get("nuclei_severity", ["critical", "high", "medium"])

        orchestrator.record_stage_start(scan_id, "scanning", "Vulnerability Scanning", 35, db=db)
        _update_scan_status(db, scan_id, "scanning", "Vulnerability Scanning", 35)
        _log(scan_id, "info", f"🔬 Starting vulnerability scanning on: {target}")

        scan_results = {"target": target, "raw_findings": []}
        tools_executed = []
        total_raw_findings = 0

        # Check if target is unreachable
        target_reachable = scan_doc.get("target_reachable")
        if target_reachable is False:
            _log(scan_id, "warning", "Target is unreachable. Active vulnerability scanning cannot proceed.")
            orchestrator.record_stage_completion(
                scan_id=scan_id,
                stage_key="scanning",
                outcome=StageOutcome.UNREACHABLE,
                summary="Vulnerability scanners skipped: target host is unreachable.",
                findings_count=0,
                tools_executed=[],
                db=db,
            )
            # Skip directly to AI reporting
            orchestrator.record_stage_skipped(scan_id, "exploitation", "Target unreachable", db=db)
            from workers.ai_worker import run_ai_analysis
            run_ai_analysis.delay(scan_id)
            return {"status": "unreachable", "scan_id": scan_id, "target": target}

        # ── Nuclei ────────────────────────────────────────────────────────────────
        if orchestrator.check_cancellation(scan_id, db=db):
            return {"status": "cancelled", "scan_id": scan_id}
        orchestrator.record_heartbeat(scan_id, "scanning", db=db)
        _update_scan_status(db, scan_id, "scanning", "Template Scanning (Nuclei)", 37)
        _log(scan_id, "info", "Running Nuclei (template-based scanning)...", "nuclei")
        try:
            nuclei = NucleiTool()
            from workers.celery_app import run_async
            result = run_async(nuclei.run(http_target, {"severities": severities}))
            _save_tool_result(db, scan_id, "nuclei", result)
            nuclei_data = result.parsed_data or {}
            findings = nuclei_data.get("findings", [])
            _store_raw_findings(db, scan_id, "nuclei", findings)
            scan_results["nuclei"] = nuclei_data
            total_raw_findings += len(findings)
            tools_executed.append("nuclei")
            _log(scan_id, "success", f"Nuclei found {len(findings)} issues", "nuclei")
        except Exception as e:
            _log(scan_id, "error", f"Nuclei failed: {e}", "nuclei")

        # ── Nikto ─────────────────────────────────────────────────────────────────
        if orchestrator.check_cancellation(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}
        orchestrator.record_heartbeat(scan_id, "scanning")
        _update_scan_status(db, scan_id, "scanning", "Web Server Scan (Nikto)", 48)
        _log(scan_id, "info", "Running Nikto (web server scan)...", "nikto")
        try:
            nikto = NiktoTool()
            from workers.celery_app import run_async
            result = run_async(nikto.run(http_target))
            _save_tool_result(db, scan_id, "nikto", result)
            nikto_data = result.parsed_data or {}
            findings = nikto_data.get("findings", [])
            _store_raw_findings(db, scan_id, "nikto", findings)
            scan_results["nikto"] = nikto_data
            total_raw_findings += len(findings)
            tools_executed.append("nikto")
            _log(scan_id, "success", f"Nikto found {len(findings)} issues", "nikto")
        except Exception as e:
            _log(scan_id, "warning", f"Nikto failed: {e}", "nikto")

        # ── Dalfox ────────────────────────────────────────────────────────────────
        if orchestrator.check_cancellation(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}
        orchestrator.record_heartbeat(scan_id, "scanning")
        _update_scan_status(db, scan_id, "scanning", "XSS Scanning (Dalfox)", 58)
        _log(scan_id, "info", "Running Dalfox (XSS scanner)...", "dalfox")
        try:
            dalfox = DalfoxTool()
            from workers.celery_app import run_async
            result = run_async(dalfox.run(http_target))
            _save_tool_result(db, scan_id, "dalfox", result)
            dalfox_data = result.parsed_data or {}
            findings = dalfox_data.get("findings", [])
            _store_raw_findings(db, scan_id, "dalfox", findings)
            scan_results["dalfox"] = dalfox_data
            total_raw_findings += len(findings)
            tools_executed.append("dalfox")
            _log(scan_id, "success", f"Dalfox found {len(findings)} XSS issues", "dalfox")
        except Exception as e:
            _log(scan_id, "warning", f"Dalfox failed: {e}", "dalfox")

        # ── ZAP ───────────────────────────────────────────────────────────────────
        if orchestrator.check_cancellation(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}
        orchestrator.record_heartbeat(scan_id, "scanning")
        _update_scan_status(db, scan_id, "scanning", "OWASP ZAP Scan", 65)
        _log(scan_id, "info", "Running OWASP ZAP (active scan)...", "zap")
        try:
            zap = ZAPTool()
            from workers.celery_app import run_async
            result = run_async(zap.run(http_target))
            _save_tool_result(db, scan_id, "zap", result)
            zap_data = result.parsed_data or {}
            findings = zap_data.get("findings", [])
            _store_raw_findings(db, scan_id, "zap", findings)
            scan_results["zap"] = zap_data
            total_raw_findings += len(findings)
            tools_executed.append("zap")
            _log(scan_id, "success", f"ZAP found {len(findings)} alerts", "zap")
        except Exception as e:
            _log(scan_id, "warning", f"ZAP failed: {e}", "zap")

        # ── Evaluate Scanning Stage Outcome ───────────────────────────────────────
        if total_raw_findings > 0:
            outcome = StageOutcome.FINDINGS_FOUND
            summary = f"Vulnerability scanning complete: {total_raw_findings} candidate vulnerabilities found."
        else:
            outcome = StageOutcome.SCANNED_WITH_NO_FINDINGS
            summary = "Vulnerability scanning complete: 0 findings discovered on target."

        orchestrator.record_stage_completion(
            scan_id=scan_id,
            stage_key="scanning",
            outcome=outcome,
            summary=summary,
            findings_count=total_raw_findings,
            tools_executed=tools_executed,
            db=db,
        )

        _update_scan_status(db, scan_id, "scanning", "Scanner Complete", 70)
        _log(scan_id, "info", f"✅ Vulnerability scanning phase complete: {summary}")

        # Trigger next phase cleanly based on exploitation config
        enable_exploit = config.get("enable_exploitation", False)
        if enable_exploit:
            from workers.exploit_worker import run_exploit
            run_exploit.delay(scan_id)
        else:
            orchestrator.record_stage_skipped(
                scan_id=scan_id,
                stage_key="exploitation",
                reason="Exploitation phase skipped (not enabled in scan configuration)",
                db=db,
            )
            from workers.ai_worker import run_ai_analysis
            run_ai_analysis.delay(scan_id)

        return {"status": "success", "scan_id": scan_id, "target": target}
    except Exception as e:
        logger.exception(f"Scanner task failed for scan {scan_id}")
        orchestrator.record_stage_completion(
            scan_id=scan_id,
            stage_key="scanning",
            outcome=StageOutcome.ERROR,
            summary=f"Vulnerability Scanning failed: {e}",
            error=str(e),
            db=db,
        )
        db["scans"].update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "error": f"Vulnerability Scanning failed: {e}"}},
        )
        _broadcast(scan_id, {"type": "progress", "phase": "Vulnerability Scanning", "percent": 0, "status": "failed"})
        raise
