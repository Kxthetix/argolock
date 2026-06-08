from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from loguru import logger

from app.config import settings
from app.database import connect_db, disconnect_db
from app.routers import health, scans, findings, reports
from app.services.websocket_manager import ws_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("🚀 VaultX backend starting up...")
    await connect_db()
    yield
    logger.info("🛑 VaultX backend shutting down...")
    await disconnect_db()


app = FastAPI(
    title="VaultX VAPT Platform",
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
