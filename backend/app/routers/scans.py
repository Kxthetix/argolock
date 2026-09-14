from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from loguru import logger

from app.database import get_db
from app.models.scan import (
    CreateScanRequest, ScanDocument, ScanStatus, ScanPhase
)
from app.services.scope_validator import validate_scope
from workers.celery_app import run_full_pipeline

router = APIRouter()


def _serialize(doc: dict) -> dict:
    """Convert MongoDB ObjectId and datetime for JSON serialization with explicit UTC 'Z' suffix."""
    if not doc:
        return doc
    doc.pop("_id", None)
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            doc[k] = v.isoformat().replace("+00:00", "Z")
        elif isinstance(v, dict):
            _serialize(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    _serialize(item)
    return doc


@router.post("", status_code=201)
async def create_scan(request: CreateScanRequest):
    """Create a new scan and enqueue the pipeline."""
    db = get_db()

    # ── Scope validation ──────────────────────────────────────────────────────
    is_valid, reason = await validate_scope(
        request.scope.target,
        request.scope.authorized,
    )
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Scope validation failed: {reason}")

    # ── Create scan document ──────────────────────────────────────────────────
    scan = ScanDocument(
        name=request.name or f"Scan of {request.scope.target}",
        scope=request.scope,
        config=request.config,
        status=ScanStatus.PENDING,
    )

    doc_data = _serialize(scan.model_dump())
    await db["scans"].insert_one(scan.model_dump())
    logger.info(f"Scan {scan.id} created for target: {request.scope.target}")

    # ── Enqueue Celery pipeline ───────────────────────────────────────────────
    run_full_pipeline.delay(scan.id, scan.model_dump())
    logger.info(f"Scan {scan.id} pipeline enqueued")

    return {"scan_id": scan.id, "status": scan.status, "message": reason}


@router.get("")
async def list_scans(skip: int = 0, limit: int = 20):
    """List all scans ordered by creation date."""
    db = get_db()
    cursor = db["scans"].find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
    scans = await cursor.to_list(length=limit)
    scans = [_serialize(s) for s in scans]
    return {"scans": scans, "skip": skip, "limit": limit}


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    """Get a single scan by ID."""
    db = get_db()
    doc = await db["scans"].find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serialize(doc)


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
):
    """Get findings for a scan, optionally filtered by severity."""
    db = get_db()

    # Verify scan exists
    scan = await db["scans"].find_one({"id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query: Dict[str, Any] = {"scan_id": scan_id}
    if severity:
        query["severity"] = {"$regex": f"^{severity.strip()}$", "$options": "i"}

    cursor = db["findings"].find(query, {"_id": 0}).sort("cvss_score", -1).skip(skip).limit(limit)
    findings = await cursor.to_list(length=limit)

    # Clean / sanitize findings on read
    from agents.vulnerability_agent import VulnerabilityAgent
    for f in findings:
        updated = False
        title = f.get("title")
        desc = f.get("description", "") or f.get("msg", "")
        tool = f.get("tool_source", "")

        if not title or title.strip() in ("", "Unknown Finding", "Unknown", "None"):
            title = (
                f.get("name")
                or f.get("template_name")
                or f.get("msg")
                or f.get("vulnerability")
                or f.get("vulnerability_type")
                or f.get("id")
            )
            if not title and desc:
                title = desc.split(".")[0].strip()
                if len(title) > 75:
                    title = title[:72] + "..."
            if not title:
                title = f"Security Issue Discovered ({tool or 'Scanner'})"
            f["title"] = title
            updated = True

        owasp = f.get("owasp_category")
        if not owasp or owasp.strip() in ("", "Unknown", "None"):
            f["owasp_category"] = VulnerabilityAgent.infer_owasp_category(f["title"], desc, tool)
            updated = True

        if updated and f.get("id"):
            await db["findings"].update_one(
                {"id": f["id"]},
                {"$set": {"title": f["title"], "owasp_category": f["owasp_category"]}}
            )

    total = await db["findings"].count_documents(query)
    findings = [_serialize(f) for f in findings]
    return {"findings": findings, "total": total, "skip": skip, "limit": limit}


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    db = get_db()
    result = await db["scans"].update_one(
        {"id": scan_id, "status": {"$in": ["pending", "running", "recon", "scanning"]}},
        {"$set": {"status": ScanStatus.CANCELLED.value, "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found or not cancellable")
    return {"message": "Scan cancelled"}




