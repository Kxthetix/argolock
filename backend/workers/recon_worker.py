"""Recon worker — runs Subfinder, Amass, Nmap, Naabu, WhatWeb, httpx-probe."""
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
from tools.nmap_tool import NmapTool
from tools.subfinder_tool import SubfinderTool
from tools.amass_tool import AmassTool
from tools.whatweb_tool import WhatWebTool
from tools.naabu_tool import NaabuTool
from tools.httpx_probe_tool import HttpxProbeTool


def _get_db_sync():
    """Get a synchronous MongoDB connection for Celery workers."""
    from pymongo import MongoClient
    from app.config import settings
    client = MongoClient(settings.mongodb_url)
    return client[settings.mongodb_db]


def _broadcast(scan_id: str, message: dict):
    """Publish WebSocket message via Redis pub/sub."""
    import redis
    import json
    from app.config import settings
    r = redis.from_url(settings.redis_url)
    r.publish(f"scan:{scan_id}", json.dumps(message))


def _update_scan_status(db, scan_id: str, status: str, phase: str, percent: int):
    db["scans"].update_one(
        {"id": scan_id},
        {"$set": {"status": status, "current_phase": phase, "progress_percent": percent}},
    )
    _broadcast(scan_id, {"type": "progress", "phase": phase, "percent": percent, "status": status})


def _log(scan_id: str, level: str, message: str, tool: str = ""):
    logger.info(f"[{scan_id}] [{tool}] {message}")
    _broadcast(scan_id, {"type": "log", "level": level, "message": message, "tool": tool})


def _save_tool_result(db, scan_id: str, tool_name: str, result):
    db["scans"].update_one(
        {"id": scan_id},
        {"$set": {f"tool_results.{tool_name}": result.model_dump()}},
    )
    _broadcast(scan_id, {"type": "tool_status", "tool": tool_name, "status": result.status})


@celery_app.task(name="workers.recon_worker.run_recon", bind=True)
def run_recon(self, scan_id: str, scan_data: dict):
    """Run all reconnaissance tools against the target."""
    db = _get_db_sync()
    target = scan_data["scope"]["target"]
    config = scan_data.get("config", {})
    is_domain = "." in target and not target.replace(".", "").isdigit()
    http_target = target if target.startswith("http") else f"http://{target}"

    _update_scan_status(db, scan_id, "recon", "Reconnaissance", 5)
    _log(scan_id, "info", f"🔍 Starting reconnaissance on target: {target}")

    recon_results = {"target": target}

    # ── Subfinder ─────────────────────────────────────────────────────────────
    if is_domain:
        _update_scan_status(db, scan_id, "recon", "Subdomain Enumeration (Subfinder)", 6)
        _log(scan_id, "info", "Running Subfinder (subdomain enumeration)...", "subfinder")
        try:
            subfinder = SubfinderTool()
            from workers.celery_app import run_async
            result = run_async(subfinder.run(target))
            _save_tool_result(db, scan_id, "subfinder", result)
            recon_results["subfinder"] = result.parsed_data or {}
            count = len(recon_results["subfinder"].get("subdomains", []))
            _log(scan_id, "success", f"Subfinder found {count} subdomains", "subfinder")
        except Exception as e:
            _log(scan_id, "warning", f"Subfinder failed: {e}", "subfinder")

    # ── Amass ─────────────────────────────────────────────────────────────────
    if is_domain:
        _update_scan_status(db, scan_id, "recon", "Subdomain Enumeration (Amass)", 9)
        _log(scan_id, "info", "Running Amass (OSINT subdomain enumeration)...", "amass")
        try:
            amass = AmassTool()
            from workers.celery_app import run_async
            result = run_async(amass.run(target))
            _save_tool_result(db, scan_id, "amass", result)
            recon_results["amass"] = result.parsed_data or {}
            count = len(recon_results["amass"].get("subdomains", []))
            _log(scan_id, "success", f"Amass found {count} subdomains", "amass")
        except Exception as e:
            _log(scan_id, "warning", f"Amass failed: {e}", "amass")

    # ── Naabu ─────────────────────────────────────────────────────────────────
    _update_scan_status(db, scan_id, "recon", "Port Discovery (Naabu)", 12)
    _log(scan_id, "info", "Running Naabu (fast port discovery)...", "naabu")
    try:
        naabu = NaabuTool()
        from workers.celery_app import run_async
        result = run_async(naabu.run(target, {"top_ports": "100"}))
        _save_tool_result(db, scan_id, "naabu", result)
        recon_results["naabu"] = result.parsed_data or {}
        ports = len(recon_results["naabu"].get("open_ports", []))
        _log(scan_id, "success", f"Naabu found {ports} open ports", "naabu")
    except Exception as e:
        _log(scan_id, "error", f"Naabu failed: {e}", "naabu")

    # ── Nmap ──────────────────────────────────────────────────────────────────
    _update_scan_status(db, scan_id, "recon", "Port Scanning (Nmap)", 16)
    _log(scan_id, "info", "Running Nmap (port scan + service detection)...", "nmap")
    try:
        nmap = NmapTool()
        nmap_opts = {"ports": config.get("nmap_ports", "top-1000")}
        from workers.celery_app import run_async
        result = run_async(nmap.run(target, nmap_opts))
        _save_tool_result(db, scan_id, "nmap", result)
        recon_results["nmap"] = result.parsed_data or {}
        ports = len(recon_results["nmap"].get("open_ports", []))
        _log(scan_id, "success", f"Nmap found {ports} open ports", "nmap")
    except Exception as e:
        _log(scan_id, "error", f"Nmap failed: {e}", "nmap")

    # ── httpx probe ───────────────────────────────────────────────────────────
    _update_scan_status(db, scan_id, "recon", "HTTP Probing (httpx)", 21)
    _log(scan_id, "info", "Running httpx (HTTP service probe)...", "httpx_probe")
    try:
        httpx_probe = HttpxProbeTool()
        from workers.celery_app import run_async
        result = run_async(httpx_probe.run(http_target))
        _save_tool_result(db, scan_id, "httpx_probe", result)
        recon_results["httpx_probe"] = result.parsed_data or {}
        live = recon_results["httpx_probe"].get("live_count", 0)
        _log(scan_id, "success", f"httpx probed {live} live endpoints", "httpx_probe")
    except Exception as e:
        _log(scan_id, "warning", f"httpx probe failed: {e}", "httpx_probe")

    # ── WhatWeb ───────────────────────────────────────────────────────────────
    _update_scan_status(db, scan_id, "recon", "Technology Fingerprinting (WhatWeb)", 26)
    _log(scan_id, "info", "Running WhatWeb (technology fingerprinting)...", "whatweb")
    try:
        whatweb = WhatWebTool()
        from workers.celery_app import run_async
        result = run_async(whatweb.run(http_target))
        _save_tool_result(db, scan_id, "whatweb", result)
        recon_results["whatweb"] = result.parsed_data or {}
        techs = len(recon_results["whatweb"].get("technologies", []))
        _log(scan_id, "success", f"WhatWeb identified {techs} technologies", "whatweb")
    except Exception as e:
        _log(scan_id, "warning", f"WhatWeb failed: {e}", "whatweb")

    _update_scan_status(db, scan_id, "recon", "Recon Complete", 30)
    _log(scan_id, "info", "✅ Reconnaissance phase complete")

    return recon_results
