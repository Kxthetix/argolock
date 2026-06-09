"""Base AI agent with prompt template loading."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from loguru import logger

from ai_providers.base_provider import BaseProvider


class BaseAgent:
    """Base class for all ArgoLock AI agents."""

    prompt_file: str = ""

    def __init__(self, provider: BaseProvider):
        self.provider = provider
        self._prompt_template = self._load_prompt()

    def _load_prompt(self) -> str:
        if not self.prompt_file:
            return ""
        prompt_path = Path(__file__).parent.parent / "prompts" / self.prompt_file
        if prompt_path.exists():
            return prompt_path.read_text(encoding="utf-8")
        return ""

    async def _complete(self, prompt: str, system: Optional[str] = None) -> str:
        """Call the provider with retry logic."""
        return await self.provider.complete_with_retry(prompt=prompt, system=system)

    def _extract_json(self, text: str) -> list | dict:
        """Extract JSON from LLM response, handling markdown code blocks."""
        # Remove markdown code blocks
        text = re.sub(r"```(?:json)?\s*", "", text)
        text = re.sub(r"```\s*", "", text)
        text = text.strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find JSON array or object
        for pattern in [r'\[.*\]', r'\{.*\}']:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    continue

        logger.warning(f"Could not extract JSON from LLM response: {text[:500]}")
        return []

    def _chunk_findings(self, findings: list, chunk_size: int = 10) -> list[list]:
        """Split findings into chunks to respect token limits."""
        return [findings[i:i+chunk_size] for i in range(0, len(findings), chunk_size)]
