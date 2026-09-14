"""
ARGOLOCK V1.7 Security Control Plane & Execution Gates
Enforces deterministic security boundaries: Scope Gate, Action Classification,
Minimum-Impact Proof Policy, and Emergency Kill Switch.
The LLM cannot override this control plane.
"""
from __future__ import annotations

import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from loguru import logger
from app.models.v1_7_models import ActionClassification, GateEvaluationResult


class SecurityControlPlane:
    """
    Deterministic gatekeeper that enforces scope, policy, action tiers,
    and safe exploitation constraints before any tool or probe runs.
    """

    # Global emergency kill switch state
    _kill_switch_active: bool = False
    _terminated_missions: Set[str] = set()

    # Known destructive patterns that must be blocked unconditionally
    DESTRUCTIVE_PATTERNS = [
        r"\bdrop\s+table\b",
        r"\bdrop\s+database\b",
        r"\bdelete\s+from\s+[a-zA-Z_0-9]+(?:\s*;|\s*$)",
        r"\btruncate\s+table\b",
        r"\brm\s+-rf\b",
        r"\bshutdown\b",
        r"\breboot\b",
        r"format\s+[a-zA-Z]:",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", # fork bomb
        r"--flush-all",
        r"--os-shell",
        r"--os-bof",
    ]

    # High impact patterns that require special authorization
    HIGH_IMPACT_PATTERNS = [
        r"\bsqlmap\b.*--dump-all",
        r"\bsqlmap\b.*--dump",
        r"--level=5",
        r"--risk=3",
        r"\bhydra\b",
        r"\bmedusa\b",
        r"\bcommix\b.*--alter-shell",
    ]

    @classmethod
    def activate_emergency_kill_switch(cls, mission_id: Optional[str] = None) -> Dict[str, Any]:
        """Activate master kill switch for all or a specific mission."""
        if mission_id:
            cls._terminated_missions.add(mission_id)
            logger.warning(f"🛑 Emergency kill switch activated for mission {mission_id}")
            return {"status": "terminated", "mission_id": mission_id, "active": True}
        else:
            cls._kill_switch_active = True
            logger.critical("🚨 GLOBAL EMERGENCY KILL SWITCH ACTIVATED! All active tool actions blocked.")
            return {"status": "all_missions_halted", "active": True}

    @classmethod
    def reset_kill_switch(cls, mission_id: Optional[str] = None) -> None:
        """Reset the kill switch."""
        if mission_id:
            cls._terminated_missions.discard(mission_id)
        else:
            cls._kill_switch_active = False
            cls._terminated_missions.clear()
        logger.info(f"Kill switch reset (mission: {mission_id or 'all'})")

    @classmethod
    def is_killed(cls, mission_id: Optional[str] = None) -> bool:
        if cls._kill_switch_active:
            return True
        if mission_id and mission_id in cls._terminated_missions:
            return True
        return False

    @classmethod
    def evaluate_scope_gate(
        cls,
        target_url_or_host: str,
        whitelist: List[str],
        blacklist: Optional[List[str]] = None,
        mission_id: Optional[str] = None,
    ) -> GateEvaluationResult:
        """
        Gate 1: Verify that target is explicitly authorized in scope whitelist
        and not prohibited in blacklist.
        """
        if cls.is_killed(mission_id):
            return GateEvaluationResult(
                allowed=False,
                gate_name="EmergencyKillSwitch",
                action_class=ActionClassification.DESTRUCTIVE,
                reason="Emergency kill switch is active for this mission",
                target=target_url_or_host,
            )

        parsed_host = cls._extract_host(target_url_or_host)
        if not parsed_host:
            return GateEvaluationResult(
                allowed=False,
                gate_name="ScopeGate",
                action_class=ActionClassification.LOW_RISK_ACTIVE,
                reason="Invalid or unparseable target host format",
                target=target_url_or_host,
            )

        # Check blacklist first
        if blacklist:
            for blocked in blacklist:
                blocked_host = cls._extract_host(blocked)
                if cls._matches_domain_or_ip(parsed_host, blocked_host):
                    return GateEvaluationResult(
                        allowed=False,
                        gate_name="ScopeGate",
                        action_class=ActionClassification.LOW_RISK_ACTIVE,
                        reason=f"Target {parsed_host} explicitly blacklisted by policy ({blocked})",
                        target=target_url_or_host,
                    )

        # If whitelist is empty or contains wildcard, allow if target format valid
        if not whitelist or "*" in whitelist:
            return GateEvaluationResult(
                allowed=True,
                gate_name="ScopeGate",
                action_class=ActionClassification.PASSIVE,
                reason=f"Target {parsed_host} authorized (open scope)",
                target=target_url_or_host,
            )

        # Validate against whitelist
        for allowed in whitelist:
            allowed_host = cls._extract_host(allowed)
            if cls._matches_domain_or_ip(parsed_host, allowed_host):
                return GateEvaluationResult(
                    allowed=True,
                    gate_name="ScopeGate",
                    action_class=ActionClassification.LOW_RISK_ACTIVE,
                    reason=f"Target {parsed_host} verified in authorized scope ({allowed})",
                    target=target_url_or_host,
                )

        return GateEvaluationResult(
            allowed=False,
            gate_name="ScopeGate",
            action_class=ActionClassification.LOW_RISK_ACTIVE,
            reason=f"Target {parsed_host} is OUT OF SCOPE. Not in authorized scope whitelist.",
            target=target_url_or_host,
        )

    @classmethod
    def evaluate_action_gate(
        cls,
        tool: str,
        command_or_action: str,
        target: str,
        safe_mode: bool = True,
    ) -> GateEvaluationResult:
        """
        Gate 2: Classify action tier and block destructive or unsafe executions.
        """
        lower_cmd = command_or_action.lower()

        # 1. Unconditional check for destructive actions
        for pattern in cls.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, lower_cmd, re.IGNORECASE):
                logger.error(f"🚨 BLOCKED DESTRUCTIVE ACTION: {command_or_action} against {target}")
                return GateEvaluationResult(
                    allowed=False,
                    gate_name="ActionClassificationGate",
                    action_class=ActionClassification.DESTRUCTIVE,
                    reason=f"Action matched prohibited destructive pattern: '{pattern}'",
                    target=target,
                )

        # 2. Check for high-impact actions when safe_mode is active
        if safe_mode:
            for pattern in cls.HIGH_IMPACT_PATTERNS:
                if re.search(pattern, lower_cmd, re.IGNORECASE):
                    return GateEvaluationResult(
                        allowed=False,
                        gate_name="ActionClassificationGate",
                        action_class=ActionClassification.HIGH_IMPACT,
                        reason="High-impact exploitation blocked while Safe Mode is enabled.",
                        target=target,
                    )

        # 3. Classify action
        action_tier = cls._classify_action(tool, lower_cmd)
        return GateEvaluationResult(
            allowed=True,
            gate_name="ActionClassificationGate",
            action_class=action_tier,
            reason=f"Action classified as {action_tier.value} and approved under safety policy.",
            target=target,
        )

    @classmethod
    def evaluate_exploitation_gate(
        cls,
        vulnerability_type: str,
        payload_or_poc: str,
        target: str,
    ) -> GateEvaluationResult:
        """
        Gate 3: Exploitation Safety Policy.
        Enforces minimum-impact proof required to establish findings without data exfiltration.
        """
        lower_payload = payload_or_poc.lower()

        # Check for mass extraction indicators
        if any(w in lower_payload for w in ["union select group_concat", "dump all", "information_schema.tables", "load_file(/etc/shadow)"]):
            return GateEvaluationResult(
                allowed=False,
                gate_name="ExploitationSafetyGate",
                action_class=ActionClassification.HIGH_IMPACT,
                reason="Policy prohibits mass credential or full database extraction. Use minimum-impact proof.",
                target=target,
            )

        return GateEvaluationResult(
            allowed=True,
            gate_name="ExploitationSafetyGate",
            action_class=ActionClassification.CONTROLLED_EXPLOITATION,
            reason="Controlled minimal proof validated under safe exploitation policy.",
            target=target,
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_host(url_or_host: str) -> str:
        s = url_or_host.strip()
        if not s.startswith("http://") and not s.startswith("https://"):
            s = "https://" + s
        try:
            parsed = urllib.parse.urlparse(s)
            host = parsed.hostname or parsed.netloc or ""
            return host.lower()
        except Exception:
            return url_or_host.strip().lower()

    @staticmethod
    def _matches_domain_or_ip(candidate: str, allowed: str) -> bool:
        if not allowed or not candidate:
            return False
        if allowed == "*":
            return True
        if candidate == allowed:
            return True
        if allowed.startswith("*.") and candidate.endswith(allowed[1:]):
            return True
        if candidate.endswith("." + allowed):
            return True
        return False

    @staticmethod
    def _classify_action(tool: str, cmd: str) -> ActionClassification:
        tool_l = tool.lower()
        if tool_l in ["subfinder", "amass", "dnsx", "assetfinder", "shuffledns", "whatweb"]:
            return ActionClassification.PASSIVE
        if tool_l in ["naabu", "nmap", "rustscan", "httpx", "httpx_probe"]:
            return ActionClassification.LOW_RISK_ACTIVE
        if tool_l in ["nuclei", "nikto", "dalfox", "zap"]:
            return ActionClassification.VALIDATION
        if tool_l in ["sqlmap", "commix", "ffuf", "hydra"]:
            return ActionClassification.CONTROLLED_EXPLOITATION
        return ActionClassification.LOW_RISK_ACTIVE
