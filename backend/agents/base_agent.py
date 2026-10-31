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

    async def _complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        mission_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> str:
        """Call the provider with retry logic and agent runtime guardrails."""
        eff_mission = mission_id or "default"
        eff_agent = agent_id or getattr(self, "agent_code", self.__class__.__name__)

        from app.services.agent_guardrails import agent_guardrails
        # Guardrail 1: Turn limit check
        agent_guardrails.check_turn_limit(eff_mission, eff_agent, raise_on_exceed=True)
        # Guardrail 2: Budget check
        agent_guardrails.check_budget(eff_mission, raise_on_exceed=True)

        agent_guardrails.record_turn(eff_mission, eff_agent)
        response = await self.provider.complete_with_retry(prompt=prompt, system=system)

        # Estimate token usage (~4 chars per token) and record usage
        prompt_tokens = max(1, len(prompt) // 4)
        completion_tokens = max(1, len(response) // 4)
        agent_guardrails.record_usage(
            eff_mission,
            prompt_tokens,
            completion_tokens,
            model_name=getattr(self.provider, "model", "default")
        )

        # Guardrail 3: Reflector check for non-action replies
        if getattr(self, "expects_action_proposals", False) and agent_guardrails.is_non_action_reply(response):
            steer = agent_guardrails.generate_reflection(eff_agent, response)
            logger.info(f"[BaseAgent] Reflector steering non-action reply from agent '{eff_agent}'")
            response = await self.provider.complete_with_retry(prompt=f"{prompt}\n\n{steer}", system=system)

        return response

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
