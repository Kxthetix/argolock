"""Abstract AI provider interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from tenacity import retry, stop_after_attempt, wait_exponential


class BaseProvider(ABC):
    """Abstract LLM provider with retry logic."""

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        """Send a completion request and return the response text."""
        ...

    async def complete_with_retry(self, *args, **kwargs) -> str:
        """Complete with automatic retries on failure."""
        for attempt in range(3):
            try:
                return await self.complete(*args, **kwargs)
            except Exception as e:
                if attempt == 2:
                    raise
                import asyncio
                await asyncio.sleep(2 ** attempt)
        raise RuntimeError("All retry attempts failed")
