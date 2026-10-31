from __future__ import annotations
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.database import get_db
from app.routers.auth import get_current_user

router = APIRouter()


@router.get("")
async def list_findings(
    severity: str = None,
    owasp_category: str = None,
    skip: int = 0,
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    db = get_db()
    user_tenant = current_user.get("tenant_id", "tenant_default")
    query = {"$or": [{"tenant_id": user_tenant}, {"tenant_id": {"$exists": False}}]}
    if severity and severity.strip().lower() not in ("undefined", "null", "all", ""):
        query["severity"] = {"$regex": f"^{severity.strip()}$", "$options": "i"}
    if owasp_category:
        query["owasp_category"] = owasp_category

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
    return {"findings": findings, "total": total}


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    db = get_db()
    doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")

    user_tenant = current_user.get("tenant_id", "tenant_default")
    doc_tenant = doc.get("tenant_id")
    if doc_tenant and doc_tenant != user_tenant:
        raise HTTPException(
            status_code=403,
            detail=f"Tenant access denied: finding belongs to another organization (user tenant: '{user_tenant}')",
        )
    return doc
