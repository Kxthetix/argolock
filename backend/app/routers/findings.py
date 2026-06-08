from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.database import get_db

router = APIRouter()


@router.get("")
async def list_findings(
    severity: str = None,
    owasp_category: str = None,
    skip: int = 0,
    limit: int = 100,
):
    db = get_db()
    query = {}
    if severity:
        query["severity"] = severity.lower()
    if owasp_category:
        query["owasp_category"] = owasp_category

    cursor = db["findings"].find(query, {"_id": 0}).sort("cvss_score", -1).skip(skip).limit(limit)
    findings = await cursor.to_list(length=limit)
    total = await db["findings"].count_documents(query)
    return {"findings": findings, "total": total}


@router.get("/{finding_id}")
async def get_finding(finding_id: str):
    db = get_db()
    doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    return doc
