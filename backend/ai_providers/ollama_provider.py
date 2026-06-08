"""Ollama local LLM provider."""
from __future__ import annotations

from typing import Optional

import httpx
from loguru import logger

from ai_providers.base_provider import BaseProvider
from app.config import settings


class OllamaProvider(BaseProvider):
    def __init__(self):
        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model

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

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("message", {}).get("content", "")
        except Exception as e:
            logger.error(f"Ollama completion failed: {e}")
            raise


# ── Factory ───────────────────────────────────────────────────────────────────

def get_provider():
    """Return the configured AI provider instance."""
    from app.config import settings
    provider = settings.ai_provider.lower()

    if provider == "openai":
        from ai_providers.openai_provider import OpenAIProvider
        return OpenAIProvider()
    elif provider == "claude":
        from ai_providers.claude_provider import ClaudeProvider
        return ClaudeProvider()
    elif provider == "ollama":
        return OllamaProvider()
    else:
        raise ValueError(f"Unknown AI provider: {provider}")
