from __future__ import annotations

import os
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from loguru import logger

from app.database import get_db
from app.config import settings

router = APIRouter()


def is_weasyprint_available() -> bool:
    """Check if WeasyPrint is functional on the server."""
    try:
        import weasyprint
        return True
    except (ImportError, OSError):
        return False


@router.get("/{scan_id}")
async def get_report(scan_id: str):
    db = get_db()
    doc = await db["reports"].find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_path = doc.get("pdf_path")
    if pdf_path:
        is_html = not is_weasyprint_available()
        # Sniff file on disk if it exists
        if os.path.exists(pdf_path):
            try:
                with open(pdf_path, "rb") as f:
                    first_bytes = f.read(200).lower()
                    if b"<!doctype" in first_bytes or b"<html" in first_bytes or b"<body" in first_bytes:
                        is_html = True
                    elif first_bytes.startswith(b"%pdf"):
                        is_html = False
            except Exception:
                pass
        
        if is_html and not pdf_path.endswith(".html"):
            doc["pdf_path"] = pdf_path.rsplit(".", 1)[0] + ".html"

    return doc


@router.get("/{scan_id}/download/pdf")
async def download_pdf(scan_id: str):
    db = get_db()
    doc = await db["reports"].find_one({"scan_id": scan_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_path = doc.get("pdf_path")
    
    # Check if a valid PDF exists on disk
    is_valid_pdf = False
    if pdf_path and os.path.exists(pdf_path):
        try:
            with open(pdf_path, "rb") as f:
                first_bytes = f.read(10).lower()
                if first_bytes.startswith(b"%pdf"):
                    is_valid_pdf = True
        except Exception:
            pass

    # If valid PDF exists, serve it
    if is_valid_pdf:
        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=f"argolock_report_{scan_id}.pdf",
        )

    # Otherwise, fall back to serving the HTML report.
    # Regenerate the HTML report on the fly if it is missing from `/tmp` (ephemeral disk wipe)
    html_filename = f"argolock_report_{scan_id}.html"
    html_path = os.path.join(settings.reports_dir, html_filename)

    if not os.path.exists(html_path):
        try:
            from reports.pdf_generator import generate_pdf
            # Pass report doc directly to regenerate the report
            # Del object id to avoid JSON serialization issues
            report_data = dict(doc)
            if "_id" in report_data:
                del report_data["_id"]
            logger.info(f"Report file missing from ephemeral disk. Regenerating report {scan_id} on the fly...")
            await generate_pdf(report_data, scan_id)
        except Exception as e:
            logger.error(f"Failed to regenerate report on the fly: {e}")

    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="Report file not found and could not be generated")

    return FileResponse(
        path=html_path,
        media_type="text/html",
        filename=html_filename,
    )


@router.get("/{scan_id}/download/json")
async def download_json(scan_id: str):
    db = get_db()
    doc = await db["reports"].find_one({"scan_id": scan_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Report not found")

    json_path = doc.get("json_path")
    
    # Regenerate JSON report on the fly if it was wiped from `/tmp`
    if not json_path or not os.path.exists(json_path):
        try:
            os.makedirs(settings.reports_dir, exist_ok=True)
            filename = f"argolock_report_{scan_id}.json"
            json_path = os.path.join(settings.reports_dir, filename)
            report_data = dict(doc)
            if "_id" in report_data:
                del report_data["_id"]
            with open(json_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to regenerate JSON report on the fly: {e}")

    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="JSON file not found on server")

    return FileResponse(
        path=json_path,
        media_type="application/json",
        filename=f"argolock_report_{scan_id}.json",
    )
