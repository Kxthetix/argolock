"""
Deterministic Policy Engine for ARGOLOCK NET v1.7.
"Agents propose and policy executes"
Enforces:
1. Agent capability allowlist (agents cannot invoke tools outside their authorized role).
2. Strict target scope verification (out-of-scope requests blocked).
3. Operator testing approvals (gate checks for Level 2/3 controlled proof).
4. Schema-validated tool JSON outputs.
5. Target content taint protection: prevents indirect prompt injection & SSRF
   when tool calls are derived from target text.
"""
from __future__ import annotations

import json
import re
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field, ConfigDict
from loguru import logger

from app.services.scope_validator import scope_validator
from app.models.vapt_models import TestingLevel, ApprovalStatus


class PolicyDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED_CAPABILITY_NOT_ALLOWED = "REJECTED_CAPABILITY_NOT_ALLOWED"
    REJECTED_OUT_OF_SCOPE = "REJECTED_OUT_OF_SCOPE"
    BLOCKED_REQUIRES_APPROVAL = "BLOCKED_REQUIRES_APPROVAL"
    REJECTED_TARGET_TAINT_INJECTION = "REJECTED_TARGET_TAINT_INJECTION"
    REJECTED_SCHEMA_INVALID = "REJECTED_SCHEMA_INVALID"


class ActionProposal(BaseModel):
    """Structured action proposal submitted by an agent for policy evaluation."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    mission_id: str
    tool: str
    target: str
    args: Dict[str, Any] = Field(default_factory=dict)
    source_text: Optional[str] = None          # Target content if proposal was derived from target
    is_tainted_by_target: bool = False
    testing_level: str = TestingLevel.LEVEL_1_NON_INVASIVE.value
    approval_id: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)


class PolicyEvaluationResult(BaseModel):
    decision: PolicyDecision
    reason: str
    executable: bool
    proposal_id: str
    agent_id: str
    tool: str
    target: str


class SchemaValidatedToolOutput(BaseModel):
    """Schema-verified JSON output structure for tools."""
    tool: str
    status: str
    exit_code: int
    parsed_data: Dict[str, Any]
    raw_preview: str = ""
    is_schema_valid: bool = True
    validation_error: Optional[str] = None


class DeterministicPolicyEngine:
    """
    Central deterministic policy authority enforcing capability boundaries,
    scope adherence, and target taint validation.
    """

    # Agent role capability allowlist: maps agent code to permitted tool IDs
    CAPABILITY_ALLOWLIST: Dict[str, Set[str]] = {
        "mission-controller": {"gateway", "policy-engine", "budget-tracker", "orchestrator"},
        "asset-discovery": {"subfinder", "amass", "assetfinder", "crtsh"},
        "dns": {"dnsx", "massdns", "dig"},
        "network-discovery": {"naabu", "nmap", "rustscan", "socket-fallback"},
        "web-surface": {"httpx", "katana", "gau", "httpx_probe"},
        "api-discovery": {"custom-crawler", "graphql-tools"},
        "vulnerability-agent": {"vuln_analyzer", "cve_matcher"},
        "vuln-agent": {"vuln_analyzer", "cve_matcher"},
        "exploit-agent": {"dalfox", "xss_probe", "dns_sec", "shannon_safe_exploit", "controlled_proof"},
        "shannon-agent": {"shannon_safe_exploit", "dalfox", "dns_sec"},
        "shannon": {"shannon_safe_exploit", "dalfox", "dns_sec"},
        "devil-advocate": {"adversarial_validator"},
        "retest-agent": {"retest_engine", "regression_probe"},
        "risk-scoring": {"risk_engine", "cvss_calculator"},
        "risk-agent": {"risk_engine", "cvss_calculator"},
        "contextual-risk": {"contextual_risk_engine"},
        "investment-optimizer": {"investment_optimizer"},
        "attack-path": {"attack_path_engine"},
        "report-agent": {"pdf_generator", "report_builder"},
        "remediation-agent": {"remediation_generator"},
    }

    # Dangerous patterns in target content (indirect prompt injection / command injection / SSRF)
    DANGEROUS_TARGET_PATTERNS = [
        re.compile(r"(?i)(ignore\s+previous\s+instructions|system:\s*override|you\s+are\s+now|bypass\s+safety)"),
        re.compile(r"(?i)(169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1|0\.0\.0\.0)"),
        re.compile(r"([;&|`]|--|\$\(|\$\{)"),  # Command chaining / shell substitution
        re.compile(r"(file:\/\/|gopher:\/\/|dict:\/\/|ldap:\/\/)"),  # Arbitrary SSRF URI schemes
    ]

    def check_capability_allowlist(self, agent_id: str, tool: str) -> Tuple[bool, str]:
        """Check if the requesting agent is permitted to invoke the tool."""
        agent_norm = agent_id.strip().lower()
        tool_norm = tool.strip().lower()

        allowed_tools = self.CAPABILITY_ALLOWLIST.get(agent_norm)
        if allowed_tools is None:
            # Check if agent has prefix match or generic mapping
            for known_agent, tools in self.CAPABILITY_ALLOWLIST.items():
                if known_agent in agent_norm or agent_norm in known_agent:
                    allowed_tools = tools
                    break

        if not allowed_tools or tool_norm not in allowed_tools:
            msg = (
                f"Capability Denied: Agent '{agent_id}' is not authorized to propose or execute "
                f"tool '{tool}' (Allowed capabilities: {list(allowed_tools) if allowed_tools else 'None'})."
            )
            logger.warning(f"[PolicyEngine] {msg}")
            return False, msg

        return True, "Capability authorized"

    def check_scope(self, target: str, authorized_scope: List[str]) -> Tuple[bool, str]:
        """Verify that the proposal target resides within the mission's authorized scope."""
        if not target or not target.strip():
            msg = "Scope Denied: Target is empty."
            logger.warning(f"[PolicyEngine] {msg}")
            return False, msg

        clean_target = target.strip().lower()
        for prefix in ("http://", "https://", "ftp://"):
            if clean_target.startswith(prefix):
                clean_target = clean_target[len(prefix):]
        host = clean_target.split("/")[0].split(":")[0]

        in_scope = scope_validator.is_target_in_scope(host, authorized_scope)
        if not in_scope:
            msg = (
                f"Scope Denied: Target host '{host}' is outside the authorized mission scope "
                f"(Allowed scope: {authorized_scope}). Action blocked."
            )
            logger.warning(f"[PolicyEngine] {msg}")
            return False, msg

        return True, "Target in scope"

    def check_target_taint(self, proposal: ActionProposal, authorized_scope: List[str]) -> Tuple[bool, str]:
        """
        Validate that any tool call constructed from target text does not contain
        indirect prompt injection, command injection, or unauthorized SSRF redirection.
        """
        source = proposal.source_text or ""
        target = proposal.target

        # Check target string itself for injection syntax
        for pat in self.DANGEROUS_TARGET_PATTERNS:
            if pat.search(target):
                msg = f"Target Taint Denied: Target '{target}' contains forbidden injection or SSRF pattern."
                logger.error(f"[PolicyEngine] {msg}")
                return False, msg

        if proposal.is_tainted_by_target or source:
            # Check source text for prompt injection steering
            for pat in self.DANGEROUS_TARGET_PATTERNS:
                if pat.search(source):
                    msg = (
                        f"Target Taint Denied: Content derived from target contains suspicious "
                        f"injection/control pattern ({pat.pattern[:25]}...). Prohibited from tool synthesis."
                    )
                    logger.error(f"[PolicyEngine] {msg}")
                    return False, msg

            # Ensure all arguments constructed from target text do not redirect outside scope
            for arg_k, arg_v in proposal.args.items():
                arg_str = str(arg_v)
                if any(arg_str.startswith(p) for p in ("http://", "https://")):
                    ok, reason = self.check_scope(arg_str, authorized_scope)
                    if not ok:
                        msg = f"Target Taint Denied: Argument '{arg_k}' points to out-of-scope destination '{arg_str}'."
                        logger.error(f"[PolicyEngine] {msg}")
                        return False, msg

        return True, "Target taint check passed"

    def check_testing_level_approval(
        self,
        testing_level: str,
        approval_record: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Gate check for execution testing level:
        - Level 0 / 1: Safe non-invasive (permitted without approval)
        - Level 2 / 3: Requires active server-side operator approval
        - Level 4: Permanently blocked
        """
        lvl = str(testing_level).lower()

        if lvl == TestingLevel.LEVEL_4_DESTRUCTIVE.value or "level_4" in lvl:
            return False, "Level 4 (Destructive testing) is permanently prohibited by policy."

        if lvl in (TestingLevel.LEVEL_2_CONTROLLED_PROOF.value, TestingLevel.LEVEL_3_OPERATOR_APPROVED.value, "level_2", "level_3"):
            if not approval_record:
                return False, f"Testing level '{lvl}' requires an approved operator record (status=approved)."

            if approval_record.get("status") != ApprovalStatus.APPROVED.value and approval_record.get("status") != "approved":
                return False, f"Operator approval is in status '{approval_record.get('status')}', not approved."

        return True, "Approval level satisfied"

    def evaluate_proposal(
        self,
        proposal: ActionProposal,
        authorized_scope: List[str],
        approval_record: Optional[Dict[str, Any]] = None,
    ) -> PolicyEvaluationResult:
        """
        Execute deterministic policy evaluation on an agent action proposal.
        """
        # 1. Capability Allowlist check
        ok, reason = self.check_capability_allowlist(proposal.agent_id, proposal.tool)
        if not ok:
            return PolicyEvaluationResult(
                decision=PolicyDecision.REJECTED_CAPABILITY_NOT_ALLOWED,
                reason=reason,
                executable=False,
                proposal_id=proposal.id,
                agent_id=proposal.agent_id,
                tool=proposal.tool,
                target=proposal.target,
            )

        # 2. Scope check
        ok, reason = self.check_scope(proposal.target, authorized_scope)
        if not ok:
            return PolicyEvaluationResult(
                decision=PolicyDecision.REJECTED_OUT_OF_SCOPE,
                reason=reason,
                executable=False,
                proposal_id=proposal.id,
                agent_id=proposal.agent_id,
                tool=proposal.tool,
                target=proposal.target,
            )

        # 3. Target taint check
        ok, reason = self.check_target_taint(proposal, authorized_scope)
        if not ok:
            return PolicyEvaluationResult(
                decision=PolicyDecision.REJECTED_TARGET_TAINT_INJECTION,
                reason=reason,
                executable=False,
                proposal_id=proposal.id,
                agent_id=proposal.agent_id,
                tool=proposal.tool,
                target=proposal.target,
            )

        # 4. Approval check
        ok, reason = self.check_testing_level_approval(proposal.testing_level, approval_record)
        if not ok:
            return PolicyEvaluationResult(
                decision=PolicyDecision.BLOCKED_REQUIRES_APPROVAL,
                reason=reason,
                executable=False,
                proposal_id=proposal.id,
                agent_id=proposal.agent_id,
                tool=proposal.tool,
                target=proposal.target,
            )

        return PolicyEvaluationResult(
            decision=PolicyDecision.APPROVED,
            reason="Proposal authorized by policy engine.",
            executable=True,
            proposal_id=proposal.id,
            agent_id=proposal.agent_id,
            tool=proposal.tool,
            target=proposal.target,
        )

    def validate_tool_output(self, tool_name: str, raw_output: str, exit_code: int = 0) -> SchemaValidatedToolOutput:
        """
        Validate that tool output conforms to expected structured JSON output schema.
        Treats unparsed or arbitrary output as untrusted.
        """
        try:
            parsed = json.loads(raw_output)
            if not isinstance(parsed, dict) and not isinstance(parsed, list):
                return SchemaValidatedToolOutput(
                    tool=tool_name,
                    status="invalid_schema",
                    exit_code=exit_code,
                    parsed_data={},
                    raw_preview=raw_output[:200],
                    is_schema_valid=False,
                    validation_error="Output JSON root is neither an object nor an array.",
                )
            parsed_dict = parsed if isinstance(parsed, dict) else {"items": parsed}
            return SchemaValidatedToolOutput(
                tool=tool_name,
                status="completed" if exit_code in (0, 1) else "failed",
                exit_code=exit_code,
                parsed_data=parsed_dict,
                raw_preview=raw_output[:200],
                is_schema_valid=True,
            )
        except Exception as e:
            logger.warning(f"[PolicyEngine] Tool '{tool_name}' output failed JSON schema validation: {e}")
            return SchemaValidatedToolOutput(
                tool=tool_name,
                status="failed_validation",
                exit_code=exit_code,
                parsed_data={},
                raw_preview=raw_output[:200],
                is_schema_valid=False,
                validation_error=str(e),
            )


# Global deterministic policy engine singleton
policy_engine = DeterministicPolicyEngine()
