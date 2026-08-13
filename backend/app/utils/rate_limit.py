"""Simple in-memory sliding-window rate limiter for auth and scan endpoints."""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import DefaultDict, List


class RateLimiter:
    def __init__(self) -> None:
        self._events: DefaultDict[str, List[float]] = defaultdict(list)
        self._lock = Lock()

    def allow(self, key: str, *, max_calls: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events[key]
            self._events[key] = [t for t in bucket if t > cutoff]
            if len(self._events[key]) >= max_calls:
                return False
            self._events[key].append(now)
            return True


rate_limiter = RateLimiter()
