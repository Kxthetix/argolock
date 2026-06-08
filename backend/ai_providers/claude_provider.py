"""Anthropic Claude provider."""
from __future__ import annotations

from typing import Optional

import anthropic
from loguru import logger

from ai_providers.base_provider import BaseProvider
from app.config import settings


class ClaudeProvider(BaseProvider):
    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        self.model = settings.anthropic_model

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system

        try:
            response = await self.client.messages.create(**kwargs)
            return response.content[0].text if response.content else ""
        except Exception as e:
            logger.error(f"Claude completion failed: {e}")
            raise
