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

from workers.celery_app import celery_app
from workers.recon_worker import _get_db_sync, _update_scan_status, _log, _save_tool_result, _broadcast
from tools.nuclei_tool import NucleiTool
from tools.nikto_tool import NiktoTool
from tools.dalfox_tool import DalfoxTool
from tools.zap_tool import ZAPTool


def _store_raw_findings(db, scan_id: str, tool: str, findings: list):
    """Store raw tool findings as pre-processed finding documents."""
    if not findings:
        return
    for f in findings:
        f["scan_id"] = scan_id
        f["tool_source"] = tool
        f["raw"] = True
    db["raw_findings"].insert_many(findings)


@celery_app.task(name="workers.scanner_worker.run_scanner", bind=True)
def run_scanner(self, recon_results: dict, scan_id: str):
    """Run all vulnerability scanners against the target."""
    db = _get_db_sync()

    scan_doc = db["scans"].find_one({"id": scan_id})
    if not scan_doc:
        logger.error(f"Scan {scan_id} not found")
        return {}

    target = scan_doc["scope"]["target"]
    http_target = target if target.startswith("http") else f"http://{target}"
    config = scan_doc.get("config", {})
    severities = config.get("nuclei_severity", ["critical", "high", "medium"])

    _update_scan_status(db, scan_id, "scanning", "Vulnerability Scanning", 35)
    _log(scan_id, "info", f"🔬 Starting vulnerability scanning on: {target}")

    scan_results = {"target": target, "raw_findings": []}

    # ── Nuclei ────────────────────────────────────────────────────────────────
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
        _log(scan_id, "success", f"Nuclei found {len(findings)} issues", "nuclei")
    except Exception as e:
        _log(scan_id, "error", f"Nuclei failed: {e}", "nuclei")

    # ── Nikto ─────────────────────────────────────────────────────────────────
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
        _log(scan_id, "success", f"Nikto found {len(findings)} issues", "nikto")
    except Exception as e:
        _log(scan_id, "warning", f"Nikto failed: {e}", "nikto")

    # ── Dalfox ────────────────────────────────────────────────────────────────
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
        _log(scan_id, "success", f"Dalfox found {len(findings)} XSS issues", "dalfox")
    except Exception as e:
        _log(scan_id, "warning", f"Dalfox failed: {e}", "dalfox")

    # ── ZAP ───────────────────────────────────────────────────────────────────
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
        _log(scan_id, "success", f"ZAP found {len(findings)} alerts", "zap")
    except Exception as e:
        _log(scan_id, "warning", f"ZAP failed: {e}", "zap")

    _update_scan_status(db, scan_id, "scanning", "Scanner Complete", 70)
    _log(scan_id, "info", "✅ Vulnerability scanning phase complete")

    return scan_results
