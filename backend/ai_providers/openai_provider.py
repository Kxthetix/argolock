"""OpenAI GPT-4o provider."""
from __future__ import annotations

from typing import Optional

from openai import AsyncOpenAI
from loguru import logger

from ai_providers.base_provider import BaseProvider
from app.config import settings


class OpenAIProvider(BaseProvider):
    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.openai_api_key, max_retries=1, timeout=10.0)
        self.model = settings.openai_model

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"OpenAI completion failed: {e}")
            raise
