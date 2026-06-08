"""AI worker — orchestrates all 4 AI agents after scanning completes."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from loguru import logger

import os
import sys

# Ensure the backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from workers.celery_app import celery_app
from workers.recon_worker import _get_db_sync, _update_scan_status, _log


@celery_app.task(name="workers.ai_worker.run_ai_analysis", bind=True)
def run_ai_analysis(self, scan_results: dict, scan_id: str):
    """Run all 4 AI agents on the collected scan data."""
    from agents.vulnerability_agent import VulnerabilityAgent
    from agents.risk_scoring_agent import RiskScoringAgent
    from agents.remediation_agent import RemediationAgent
    from agents.report_agent import ReportAgent
    from ai_providers import get_provider
    import asyncio

    db = _get_db_sync()
    scan_doc = db["scans"].find_one({"id": scan_id})
    if not scan_doc:
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

    # Save findings to DB
    if remediated_findings:
        finding_dicts = [f if isinstance(f, dict) else f.model_dump() for f in remediated_findings]
        import copy
        db["findings"].insert_many(copy.deepcopy(finding_dicts))

        # Update counts on scan
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in finding_dicts:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        db["scans"].update_one(
            {"id": scan_id},
            {"$set": {
                "finding_count": len(finding_dicts),
                "critical_count": counts["critical"],
                "high_count": counts["high"],
                "medium_count": counts["medium"],
                "low_count": counts["low"],
            }}
        )

        # Broadcast each finding to dashboard
        import redis, json
        from app.config import settings
        r = redis.from_url(settings.redis_url)
        for f in finding_dicts[:20]:  # Cap broadcast to 20 findings
            r.publish(f"scan:{scan_id}", json.dumps({"type": "finding", "finding": f}))

    # ── Agent 4: Report Generator ─────────────────────────────────────────────
    _update_scan_status(db, scan_id, "reporting", "Generating Report", 93)
    _log(scan_id, "info", "Agent 4: Generating professional security report...", "report-agent")
    try:
        agent4 = ReportAgent(provider)
        report = run_async(
            agent4.generate(scan_id, scan_doc, remediated_findings)
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
            "completed_at": datetime.utcnow().isoformat(),
        }}
    )
    _log(scan_id, "success", "🎉 VaultX scan complete! View your report in the dashboard.")

    import redis, json
    from app.config import settings
    r = redis.from_url(settings.redis_url)
    r.publish(f"scan:{scan_id}", json.dumps({
        "type": "progress", "phase": "Complete", "percent": 100, "status": "completed"
    }))
