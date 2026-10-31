"""
Agent Runtime Guardrails for ARGOLOCK NET v1.7.
Implements:
1. Per-agent turn limits
2. Repeat-call and oscillating loop detection
3. Reflector for non-action or conversational replies
4. Token and cost budget tracking per mission
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field
from loguru import logger


class TurnLimitExceededException(Exception):
    """Raised when an agent exceeds its maximum permitted interaction turns."""
    pass


class RepeatCallLoopException(Exception):
    """Raised when an agent enters an infinite repeat-call or oscillating loop."""
    pass


class BudgetExceededException(Exception):
    """Raised when mission token or monetary budget is exhausted."""
    pass


class MissionUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class AgentGuardrails:
    """Runtime supervisor enforcing execution limits, safety interlocks, and loop prevention."""

    # Default pricing per 1,000 tokens (USD)
    COST_RATES = {
        "default": {"prompt": 0.0025, "completion": 0.010},
        "gpt-4o": {"prompt": 0.0025, "completion": 0.010},
        "claude-3-5-sonnet": {"prompt": 0.003, "completion": 0.015},
        "gemini-1.5-pro": {"prompt": 0.00125, "completion": 0.005},
        "mock-provider": {"prompt": 0.0001, "completion": 0.0002},
    }

    def __init__(
        self,
        default_max_turns: int = 10,
        default_repeat_threshold: int = 3,
        default_max_tokens: int = 100_000,
        default_max_cost_usd: float = 5.0,
    ):
        self.default_max_turns = default_max_turns
        self.default_repeat_threshold = default_repeat_threshold
        self.default_max_tokens = default_max_tokens
        self.default_max_cost_usd = default_max_cost_usd

        # State storage (in-memory per runtime lifecycle)
        self._turn_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._call_histories: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        self._mission_usage: Dict[str, MissionUsage] = defaultdict(MissionUsage)

    # ── 1. Turn Limits ──────────────────────────────────────────────────────────

    def record_turn(self, mission_id: str, agent_id: str) -> int:
        """Increment and return the current turn count for the specified agent."""
        self._turn_counters[mission_id][agent_id] += 1
        current = self._turn_counters[mission_id][agent_id]
        logger.debug(f"[Guardrails] Agent {agent_id} in mission {mission_id} on turn {current}")
        return current

    def get_turns(self, mission_id: str, agent_id: str) -> int:
        """Get the current turn count."""
        return self._turn_counters[mission_id][agent_id]

    def check_turn_limit(
        self,
        mission_id: str,
        agent_id: str,
        max_turns: Optional[int] = None,
        raise_on_exceed: bool = True,
    ) -> bool:
        """
        Verify if the agent has reached or exceeded its turn limit.
        Returns False (or raises TurnLimitExceededException) when limit is exceeded.
        """
        limit = max_turns if max_turns is not None else self.default_max_turns
        current = self._turn_counters[mission_id][agent_id]
        if current >= limit:
            msg = (
                f"Agent '{agent_id}' exceeded maximum turn limit ({current} >= {limit}) "
                f"in mission '{mission_id}'."
            )
            logger.warning(f"[Guardrails] {msg}")
            if raise_on_exceed:
                raise TurnLimitExceededException(msg)
            return False
        return True

    # ── 2. Repeat-Call & Loop Detection ─────────────────────────────────────────

    def _call_signature(self, tool: str, args: Dict[str, Any], target: str) -> str:
        """Generate a deterministic signature hash for a tool call proposal."""
        normalized = {
            "tool": tool.strip().lower(),
            "target": target.strip().lower(),
            "args": args,
        }
        raw_json = json.dumps(normalized, sort_keys=True, default=str)
        return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    def check_and_record_call(
        self,
        mission_id: str,
        agent_id: str,
        tool: str,
        target: str,
        args: Dict[str, Any],
        repeat_threshold: Optional[int] = None,
        raise_on_loop: bool = True,
    ) -> Tuple[bool, str]:
        """
        Detects repeating identical calls or oscillating loops.
        Returns:
            (is_loop, reason)
        """
        threshold = repeat_threshold if repeat_threshold is not None else self.default_repeat_threshold
        sig = self._call_signature(tool, args, target)
        key = f"{mission_id}::{agent_id}"
        history = self._call_histories[key]

        # Check 1: Consecutive identical proposals
        recent_identical = 0
        for prev_sig in reversed(history):
            if prev_sig == sig:
                recent_identical += 1
            else:
                break

        if recent_identical + 1 >= threshold:
            msg = (
                f"Loop detected: Agent '{agent_id}' proposed identical action '{tool}' "
                f"on '{target}' {recent_identical + 1} times consecutively."
            )
            logger.warning(f"[Guardrails] {msg}")
            if raise_on_loop:
                raise RepeatCallLoopException(msg)
            return True, msg

        # Check 2: Oscillating cycle detection (e.g. A -> B -> A -> B)
        history_list = list(history) + [sig]
        if len(history_list) >= 4:
            if history_list[-1] == history_list[-3] and history_list[-2] == history_list[-4]:
                msg = (
                    f"Oscillating loop detected: Agent '{agent_id}' alternating between "
                    f"repeated actions without forward progress."
                )
                logger.warning(f"[Guardrails] {msg}")
                if raise_on_loop:
                    raise RepeatCallLoopException(msg)
                return True, msg

        history.append(sig)
        return False, ""

    # ── 3. Reflector for Non-Action Replies ──────────────────────────────────────

    def is_non_action_reply(self, response_text: str) -> bool:
        """
        Examines an LLM agent response to verify whether it contains an actionable
        structured tool invocation/proposal or merely conversational prose/refusal.
        """
        text = response_text.strip().lower()
        if not text:
            return True

        # Check for conversational refusal or boilerplate prefixes
        conversational_patterns = [
            r"^i cannot\b",
            r"^i am unable\b",
            r"^i'm sorry\b",
            r"^as an ai\b",
            r"^sure, i can help\b",
            r"^hello[!,.]?",
            r"^certainly!",
            r"^here is an explanation\b",
            r"^in summary\b",
        ]
        for pat in conversational_patterns:
            if re.search(pat, text):
                return True

        # Check if response has structured JSON action proposal
        has_json = ("{" in text and "}" in text) or ("[" in text and "]" in text)
        if not has_json:
            return True

        return False

    def generate_reflection(
        self,
        agent_id: str,
        reply_text: str,
        expected_schema_desc: str = "JSON action proposal with 'tool', 'target', and 'args'",
    ) -> str:
        """Generate an autonomous corrective steering message for the agent."""
        excerpt = reply_text[:200] if reply_text else "(empty)"
        return (
            f"[SYSTEM REFLECTOR]: Your previous output did not produce a valid executable action proposal.\n"
            f"Observed output excerpt: {excerpt}\n"
            f"Rule: Conversational chatter, apologies, and explanations outside structured JSON are forbidden.\n"
            f"Please propose your next action strictly conforming to: {expected_schema_desc}."
        )

    # ── 4. Token & Cost Budgeting ───────────────────────────────────────────────

    def record_usage(
        self,
        mission_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        model_name: str = "default",
    ) -> MissionUsage:
        """Accumulate token consumption and update estimated cost in USD."""
        rates = self.COST_RATES.get(model_name.lower()) or self.COST_RATES["default"]
        cost = (
            (prompt_tokens / 1000.0) * rates["prompt"]
            + (completion_tokens / 1000.0) * rates["completion"]
        )

        usage = self._mission_usage[mission_id]
        usage.prompt_tokens += prompt_tokens
        usage.completion_tokens += completion_tokens
        usage.total_tokens += (prompt_tokens + completion_tokens)
        usage.estimated_cost_usd += cost

        logger.debug(
            f"[Guardrails] Mission {mission_id} usage: {usage.total_tokens} tokens, "
            f"${usage.estimated_cost_usd:.4f} USD"
        )
        return usage

    def get_mission_usage(self, mission_id: str) -> MissionUsage:
        """Get total resource consumption for a mission."""
        return self._mission_usage[mission_id]

    def check_budget(
        self,
        mission_id: str,
        max_tokens: Optional[int] = None,
        max_cost_usd: Optional[float] = None,
        raise_on_exceed: bool = True,
    ) -> Tuple[bool, str]:
        """
        Validate whether the mission has exceeded its token or monetary budget.
        Returns:
            (within_budget, message)
        """
        token_cap = max_tokens if max_tokens is not None else self.default_max_tokens
        cost_cap = max_cost_usd if max_cost_usd is not None else self.default_max_cost_usd

        usage = self._mission_usage[mission_id]

        if usage.total_tokens >= token_cap:
            msg = (
                f"Mission '{mission_id}' exceeded token budget: "
                f"{usage.total_tokens} >= {token_cap} tokens."
            )
            logger.warning(f"[Guardrails] {msg}")
            if raise_on_exceed:
                raise BudgetExceededException(msg)
            return False, msg

        if usage.estimated_cost_usd >= cost_cap:
            msg = (
                f"Mission '{mission_id}' exceeded monetary budget: "
                f"${usage.estimated_cost_usd:.4f} >= ${cost_cap:.2f} USD."
            )
            logger.warning(f"[Guardrails] {msg}")
            if raise_on_exceed:
                raise BudgetExceededException(msg)
            return False, msg

        return True, "Within budget"

    def reset_mission(self, mission_id: str) -> None:
        """Clear mission tracking state upon mission completion."""
        self._turn_counters.pop(mission_id, None)
        self._mission_usage.pop(mission_id, None)
        # Clear call history for this mission
        keys_to_remove = [k for k in self._call_histories.keys() if k.startswith(f"{mission_id}::")]
        for k in keys_to_remove:
            self._call_histories.pop(k, None)


# Global singleton instance
agent_guardrails = AgentGuardrails()
