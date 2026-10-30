"""Per-tool concurrency limiter to enforce execution bounds across concurrent scans."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Optional
from loguru import logger

# Default concurrency limits per tool
DEFAULT_TOOL_LIMITS = {
    "nmap": 2,
    "nuclei": 2,
    "sqlmap": 2,
    "zap": 1,
    "dalfox": 3,
    "nikto": 2,
    "subfinder": 4,
    "amass": 2,
    "httpx_probe": 4,
    "whatweb": 4,
    "shannon": 4,
}


class ToolConcurrencyLimiter:
    """Controls max concurrent executions for resource-intensive security tools."""

    def __init__(self, limits: Optional[Dict[str, int]] = None):
        self._limits = limits or dict(DEFAULT_TOOL_LIMITS)
        self._semaphores: Dict[str, asyncio.Semaphore] = {}

    def _get_semaphore(self, tool_name: str) -> asyncio.Semaphore:
        clean_name = tool_name.lower().strip()
        if clean_name not in self._semaphores:
            limit = self._limits.get(clean_name, 2)
            self._semaphores[clean_name] = asyncio.Semaphore(limit)
        return self._semaphores[clean_name]

    @asynccontextmanager
    async def acquire(self, tool_name: str):
        """Acquire a slot for the specified tool."""
        sem = self._get_semaphore(tool_name)
        await sem.acquire()
        try:
            yield
        finally:
            sem.release()


tool_limiter = ToolConcurrencyLimiter()
