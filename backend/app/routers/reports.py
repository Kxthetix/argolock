from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.database import get_db
from app.config import settings

router = APIRouter()


@router.get("/{scan_id}")
async def get_report(scan_id: str):
    db = get_db()
    doc = await db["reports"].find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")
    return doc


@router.get("/{scan_id}/download/pdf")
async def download_pdf(scan_id: str):
    db = get_db()
    doc = await db["reports"].find_one({"scan_id": scan_id})
    if not doc or not doc.get("pdf_path"):
        raise HTTPException(status_code=404, detail="PDF report not generated yet")

    pdf_path = doc["pdf_path"]
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF file not found on server")

    if pdf_path.endswith(".html"):
        return FileResponse(
            path=pdf_path,
            media_type="text/html",
            filename=f"argolock_report_{scan_id}.html",
        )

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"argolock_report_{scan_id}.pdf",
    )


@router.get("/{scan_id}/download/json")
async def download_json(scan_id: str):
    db = get_db()
    doc = await db["reports"].find_one({"scan_id": scan_id})
    if not doc or not doc.get("json_path"):
        raise HTTPException(status_code=404, detail="JSON report not generated yet")

    json_path = doc["json_path"]
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="JSON file not found on server")

    return FileResponse(
        path=json_path,
        media_type="application/json",
        filename=f"argolock_report_{scan_id}.json",
    )
