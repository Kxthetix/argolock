"""AI worker — orchestrates all 4 AI agents after scanning completes."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from loguru import logger

import os
import sys

# Ensure the backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from workers.celery_app import celery_app
from workers.recon_worker import _get_db_sync, _update_scan_status, _log, _broadcast


@celery_app.task(name="workers.ai_worker.run_ai_analysis", bind=True)
def run_ai_analysis(self, scan_results_or_scan_id: Any, scan_id: str | None = None):
    """Run all 4 AI agents on the collected scan data."""
    if scan_id is None:
        scan_id = scan_results_or_scan_id
        scan_results = None
    else:
        scan_results = scan_results_or_scan_id

    db = None
    try:
        db = _get_db_sync()
        from agents.vulnerability_agent import VulnerabilityAgent
        from agents.risk_scoring_agent import RiskScoringAgent
        from agents.remediation_agent import RemediationAgent
        from agents.report_agent import ReportAgent
        from ai_providers import get_provider
        import asyncio

        scan_doc = db["scans"].find_one({"id": scan_id})
        if not scan_doc:
            logger.warning(f"Scan {scan_id} not found in database")
            return

        _update_scan_status(db, scan_id, "ai_analysis", "AI Analysis", 75)
        _log(scan_id, "info", "🤖 Starting AI agent pipeline...")

        # Load raw findings
        raw_findings = list(db["raw_findings"].find({"scan_id": scan_id}, {"_id": 0}))
        _log(scan_id, "info", f"Processing {len(raw_findings)} raw findings through AI agents")

        provider = get_provider()
        from workers.celery_app import run_async

        # ── Agent 1: Vulnerability Analyzer ──────────────────────────────────────
        _log(scan_id, "info", "Agent 1: Analyzing and deduplicating vulnerabilities...", "vuln-agent")
        try:
            agent1 = VulnerabilityAgent(provider)
            findings = run_async(
                agent1.analyze(raw_findings, scan_id, scan_doc["scope"]["target"])
            )
            _log(scan_id, "success", f"Agent 1 produced {len(findings)} unique findings", "vuln-agent")
        except Exception as e:
            _log(scan_id, "error", f"Vulnerability agent failed: {e}", "vuln-agent")
            findings = []

        # ── Agent 2: Risk Scoring ─────────────────────────────────────────────────
        _update_scan_status(db, scan_id, "ai_analysis", "Risk Scoring", 82)
        _log(scan_id, "info", "Agent 2: Calculating CVSS risk scores...", "risk-agent")
        try:
            agent2 = RiskScoringAgent(provider)
            scored_findings = run_async(agent2.score(findings))
            _log(scan_id, "success", "Agent 2 risk scoring complete", "risk-agent")
        except Exception as e:
            _log(scan_id, "error", f"Risk scoring agent failed: {e}", "risk-agent")
            scored_findings = findings

        # ── Agent 3: Remediation ──────────────────────────────────────────────────
        _update_scan_status(db, scan_id, "ai_analysis", "Generating Remediations", 88)
        _log(scan_id, "info", "Agent 3: Generating root cause and remediation steps...", "remediation-agent")
        try:
            agent3 = RemediationAgent(provider)
            remediated_findings = run_async(agent3.remediate(scored_findings))
            _log(scan_id, "success", "Agent 3 remediation generation complete", "remediation-agent")
        except Exception as e:
            _log(scan_id, "error", f"Remediation agent failed: {e}", "remediation-agent")
            remediated_findings = scored_findings

        # Save verified findings to DB (DataSource mandatory, HYPOTHESIS never persisted/reported)
        finding_dicts = []
        if remediated_findings:
            raw_dicts = [f if isinstance(f, dict) else f.model_dump() for f in remediated_findings]
            for f in raw_dicts:
                ds = str(f.get("data_source") or "TOOL_OUTPUT").upper()
                if ds == "HYPOTHESIS":
                    logger.warning(f"Discarding hypothetical finding '{f.get('title')}' from scan {scan_id} — HYPOTHESIS is never reported.")
                    continue
                f["data_source"] = ds
                finding_dicts.append(f)

            if finding_dicts:
                import copy
                db["findings"].insert_many(copy.deepcopy(finding_dicts))

            # Update counts on scan
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in finding_dicts:
                sev = str(f.get("severity", "info")).lower()
                f["severity"] = sev
                counts[sev] = counts.get(sev, 0) + 1

            db["scans"].update_one(
                {"id": scan_id},
                {"$set": {
                    "finding_count": len(finding_dicts),
                    "critical_count": counts["critical"],
                    "high_count": counts["high"],
                    "medium_count": counts["medium"],
                    "low_count": counts["low"],
                    "info_count": counts["info"],
                }}
            )

            # Broadcast each finding to dashboard
            for f in finding_dicts[:20]:  # Cap broadcast to 20 findings
                _broadcast(scan_id, {"type": "finding", "finding": f})
        else:
            db["scans"].update_one(
                {"id": scan_id},
                {"$set": {
                    "finding_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "info_count": 0,
                }}
            )

        # ── Agent 4: Report Generator ─────────────────────────────────────────────
        _update_scan_status(db, scan_id, "reporting", "Generating Report", 93)
        _log(scan_id, "info", "Agent 4: Generating professional security report...", "report-agent")
        
        # Determine target reachability and assessment coverage
        tr = scan_doc.get("tool_results", {})
        open_ports = (tr.get("nmap", {}).get("parsed_data") or {}).get("open_ports", []) or \
                     (tr.get("naabu", {}).get("parsed_data") or {}).get("open_ports", [])
        live_endpoints = (tr.get("httpx_probe", {}).get("parsed_data") or {}).get("probes", [])

        target_reachable = bool(open_ports or live_endpoints)
        coverage_level = "full" if (target_reachable and len(open_ports) > 0 and len(live_endpoints) > 0) else ("partial" if target_reachable else "none")
        coverage_summary = "none" if not target_reachable else f"{coverage_level} coverage"

        scan_doc["coverage"] = coverage_level
        scan_doc["coverage_summary"] = coverage_summary
        scan_doc["target_reachable"] = target_reachable

        db["scans"].update_one(
            {"id": scan_id},
            {"$set": {
                "coverage": coverage_level,
                "coverage_summary": coverage_summary,
                "target_reachable": target_reachable,
            }}
        )

        try:
            agent4 = ReportAgent(provider)
            report = run_async(
                agent4.generate(scan_id, scan_doc, finding_dicts)
            )
            db["reports"].insert_one({**report, "_inserted": True})
            db["reports"].update_one({"_inserted": True}, {"$unset": {"_inserted": 1}})
            _log(scan_id, "success", "Agent 4 report generation complete", "report-agent")
        except Exception as e:
            _log(scan_id, "error", f"Report agent failed: {e}", "report-agent")

        # ── Complete ──────────────────────────────────────────────────────────────
        db["scans"].update_one(
            {"id": scan_id},
            {"$set": {
                "status": "completed",
                "current_phase": "Complete",
                "progress_percent": 100,
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }}
        )
        _log(scan_id, "success", "🎉 ArgoLock scan complete! View your report in the dashboard.")

        _broadcast(scan_id, {
            "type": "progress", "phase": "Complete", "percent": 100, "status": "completed"
        })
    except Exception as e:
        import os
        import sys
        err_msg = f"AI Analysis failed: {e}. sys.path={sys.path}, cwd={os.getcwd()}"
        logger.exception(err_msg)
        if db is not None:
            try:
                db["scans"].update_one(
                    {"id": scan_id},
                    {"$set": {"status": "failed", "error": err_msg}},
                )
                _broadcast(scan_id, {"type": "progress", "phase": "AI Analysis", "percent": 0, "status": "failed"})
            except Exception as db_err:
                logger.error(f"Failed to update database status: {db_err}")
        raise
