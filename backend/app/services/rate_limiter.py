"""
ARGOLOCK V1.7 Rate Limiter Service
Sliding-window rate limiter per tenant and client IP.
Enforces burst control and denial-of-service defense across critical endpoints.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import HTTPException, Request, status
from loguru import logger


class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self):
        # Maps key -> list of request timestamps (epoch floats)
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(
        self,
        key: str,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, int, int]:
        """
        Check whether an action identified by `key` is permitted under the rate limit.
        Returns: (is_allowed, limit, remaining, reset_seconds)
        """
        now = time.time()
        window_start = now - window_seconds

        # Prune expired timestamps
        timestamps = [t for t in self._requests[key] if t > window_start]
        self._requests[key] = timestamps

        current_count = len(timestamps)
        if current_count >= max_requests:
            # Exceeded limit
            oldest = timestamps[0] if timestamps else window_start
            reset_seconds = max(1, int(oldest + window_seconds - now))
            return False, max_requests, 0, reset_seconds

        # Allow and record request
        self._requests[key].append(now)
        remaining = max_requests - (current_count + 1)
        reset_seconds = window_seconds
        return True, max_requests, remaining, reset_seconds

    def check_rate_limit(
        self,
        key: str,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> Dict[str, str]:
        """
        Enforce rate limit. If exceeded, raises HTTP 429 Too Many Requests.
        Returns response headers on success.
        """
        allowed, limit, remaining, reset_seconds = self.is_allowed(
            key=key,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_seconds),
        }

        if not allowed:
            headers["Retry-After"] = str(reset_seconds)
            logger.warning(f"⚠️ [RATE_LIMIT] Rate limit exceeded for key='{key}' (limit={limit}/{window_seconds}s)")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: maximum {limit} requests per {window_seconds} seconds. Try again in {reset_seconds}s.",
                headers=headers,
            )

        return headers

    def reset(self, key: Optional[str] = None):
        """Reset history for a key or all keys (useful for testing)."""
        if key:
            self._requests.pop(key, None)
        else:
            self._requests.clear()


rate_limiter = SlidingWindowRateLimiter()
