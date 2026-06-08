"""WebSocket connection manager for real-time scan log streaming."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Dict, List

from fastapi import WebSocket
from loguru import logger


class WebSocketManager:
    """Manages WebSocket connections grouped by scan_id."""

    def __init__(self):
        # scan_id -> list of active WebSocket connections
        self._connections: Dict[str, List[WebSocket]] = defaultdict(list)

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[scan_id].append(websocket)
        logger.info(f"WebSocket connected for scan {scan_id} (total: {len(self._connections[scan_id])})")

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        if scan_id in self._connections:
            try:
                self._connections[scan_id].remove(websocket)
            except ValueError:
                pass
            if not self._connections[scan_id]:
                del self._connections[scan_id]
        logger.info(f"WebSocket disconnected for scan {scan_id}")

    async def broadcast(self, scan_id: str, message: Dict[str, Any]) -> None:
        """Send a message to all connections watching a scan."""
        connections = self._connections.get(scan_id, [])
        if not connections:
            return

        dead_connections = []
        for ws in connections:
            try:
                await ws.send_json(message)
            except Exception as exc:
                logger.warning(f"WebSocket send failed for scan {scan_id}: {exc}")
                dead_connections.append(ws)

        # Clean up dead connections
        for ws in dead_connections:
            self.disconnect(scan_id, ws)

    async def send_log(self, scan_id: str, level: str, message: str, tool: str = "") -> None:
        """Convenience method to broadcast a log line."""
        await self.broadcast(scan_id, {
            "type": "log",
            "level": level,
            "message": message,
            "tool": tool,
        })

    async def send_progress(self, scan_id: str, phase: str, percent: int, status: str) -> None:
        """Broadcast scan progress update."""
        await self.broadcast(scan_id, {
            "type": "progress",
            "phase": phase,
            "percent": percent,
            "status": status,
        })

    async def send_finding(self, scan_id: str, finding: Dict[str, Any]) -> None:
        """Broadcast a newly discovered finding."""
        await self.broadcast(scan_id, {
            "type": "finding",
            "finding": finding,
        })

    async def send_tool_status(self, scan_id: str, tool: str, status: str) -> None:
        """Broadcast tool execution status change."""
        await self.broadcast(scan_id, {
            "type": "tool_status",
            "tool": tool,
            "status": status,
        })


# Singleton instance
ws_manager = WebSocketManager()
