from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from loguru import logger

from app.config import settings
from app.database import connect_db, disconnect_db
from app.routers import health, scans, findings, reports, auth, system, vapt_router
from app.services.websocket_manager import ws_manager


async def redis_pubsub_listener():
    import redis.asyncio as aioredis
    import json
    
    logger.info("Starting Redis pub/sub listener background task...")
    while True:
        try:
            r = aioredis.from_url(settings.redis_url)
            pubsub = r.pubsub()
            await pubsub.psubscribe("scan:*")
            logger.info("Subscribed to scan:* channel pattern on Redis")
            async for message in pubsub.listen():
                if message["type"] == "pmessage":
                    channel = message["channel"].decode("utf-8")
                    data = message["data"].decode("utf-8")
                    parts = channel.split(":")
                    if len(parts) >= 2:
                        scan_id = parts[1]
                        try:
                            payload = json.loads(data)
                            await ws_manager.broadcast(scan_id, payload)
                        except Exception as e:
                            logger.error(f"Error parsing/broadcasting Redis message: {e}")
        except asyncio.CancelledError:
            logger.info("Redis pub/sub listener background task cancelled.")
            break
        except Exception as e:
            logger.error(f"Redis pubsub connection error: {e}. Retrying in 5 seconds...")
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("🚀 ArgoLock backend starting up...")
    await connect_db()
    
    # ── Startup database cleanup ──────────────────────────────────────────────
    try:
        from datetime import datetime, timezone
        from app.database import get_db
        db = get_db()
        ongoing_statuses = ["pending", "running", "recon", "scanning", "exploiting", "ai_analysis", "reporting"]
        result = await db["scans"].update_many(
            {"status": {"$in": ongoing_statuses}},
            {"$set": {
                "status": "failed",
                "error": "Scan interrupted due to server restart",
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }}
        )
        if result.modified_count > 0:
            logger.info(f"🧹 Cleaned up {result.modified_count} interrupted scan(s) from database.")

        # ── Startup auto-repair for findings ─────────────────────────────────
        from agents.vulnerability_agent import VulnerabilityAgent
        cursor = db["findings"].find({
            "$or": [
                {"title": {"$in": ["Unknown Finding", "Unknown", "", None]}},
                {"owasp_category": {"$in": ["Unknown", "", None]}}
            ]
        })
        unfixed_findings = await cursor.to_list(length=1000)
        repaired_count = 0
        for f in unfixed_findings:
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

            owasp = f.get("owasp_category")
            if not owasp or owasp.strip() in ("", "Unknown", "None"):
                f["owasp_category"] = VulnerabilityAgent.infer_owasp_category(f["title"], desc, tool)

            await db["findings"].update_one(
                {"id": f["id"]},
                {"$set": {"title": f["title"], "owasp_category": f["owasp_category"]}}
            )
            repaired_count += 1
        if repaired_count > 0:
            logger.info(f"✨ Auto-repaired {repaired_count} finding(s) with missing title or OWASP category.")
    except Exception as e:
        logger.error(f"Failed to clean up interrupted scans or repair findings on startup: {e}")
    
    # Start Redis listener task
    listener_task = asyncio.create_task(redis_pubsub_listener())
    
    yield
    
    logger.info("🛑 ArgoLock backend shutting down...")
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass
    await disconnect_db()


app = FastAPI(
    title="ArgoLock VAPT Platform",
    description="AI-powered Vulnerability Assessment & Penetration Testing platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(system.router, prefix="/api/system", tags=["System"])
app.include_router(vapt_router.router, prefix="/api/vapt", tags=["VAPT Validation"])

# ── WebSocket ─────────────────────────────────────────────────────────────────
from fastapi import WebSocket, WebSocketDisconnect


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str):
    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            # Keep connection alive; server pushes events
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
    except Exception as exc:
        logger.error(f"WebSocket error for scan {scan_id}: {exc}")
        ws_manager.disconnect(scan_id, websocket)
