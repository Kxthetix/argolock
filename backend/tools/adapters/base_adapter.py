"""Base Tool Adapter interface for ARGOLOCK NET v1.6."""
from __future__ import annotations

import abc
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger


class ToolAdapter(abc.ABC):
    """
    Standard interface for all ARGOLOCK security testing and validation tool integrations.
    """
    tool_id: str = "base"
    name: str = "Base Tool"
    category: str = "discovery"  # discovery, web_api, vulnerability, windows_ad, cloud, code, intelligence
    supported_levels: List[str] = ["level_0", "level_1"]

    def __init__(self, execution_mode: str = "subprocess"):
        self.execution_mode = execution_mode
        self.last_health_check: Optional[datetime] = None
        self.last_execution: Optional[datetime] = None
        self.execution_count: int = 0
        self.success_count: int = 0

    @abc.abstractmethod
    def check_installation(self) -> bool:
        """Verify whether the tool binary or service is reachable and runnable."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_version(self) -> str:
        """Return the installed tool version string or 'unknown'."""
        raise NotImplementedError

    def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check and return status report."""
        installed = self.check_installation()
        version = self.get_version() if installed else "not_installed"
        config_valid = self.validate_configuration()
        self.last_health_check = datetime.now(timezone.utc)
        success_rate = (self.success_count / self.execution_count * 100.0) if self.execution_count > 0 else 100.0

        status = "READY" if (installed and config_valid) else ("CONFIGURED" if config_valid else "UNAVAILABLE")

        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "installed": installed,
            "version": version,
            "configuration_valid": config_valid,
            "health_status": status,
            "last_check": self.last_health_check.isoformat().replace("+00:00", "Z"),
            "execution_count": self.execution_count,
            "success_rate": round(success_rate, 1),
            "capabilities": self.get_capabilities(),
        }

    def validate_configuration(self) -> bool:
        """Validate configuration settings, template paths, or credentials."""
        return True

    @abc.abstractmethod
    def build_test(self, target: str, context: Dict[str, Any]) -> Any:
        """Construct the execution parameters/arguments for validation."""
        raise NotImplementedError

    @abc.abstractmethod
    async def execute_validation(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the non-destructive validation test against the target."""
        raise NotImplementedError

    @abc.abstractmethod
    def parse_result(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse raw output into structured finding candidates."""
        raise NotImplementedError

    @abc.abstractmethod
    def collect_evidence(self, raw_output: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract proof artifacts (request/response/banner/output) for verification."""
        raise NotImplementedError

    def normalize_result(
        self,
        finding_id: str,
        asset_id: str,
        status: str,
        confidence: float,
        evidence: List[Dict[str, Any]],
        cve: Optional[str] = None,
        cwe: Optional[str] = None,
        severity: str = "medium",
        execution_status: str = "completed",
    ) -> Dict[str, Any]:
        """Emit standardized ARGOLOCK validation result schema."""
        return {
            "tool": self.tool_id,
            "asset_id": asset_id,
            "finding_id": finding_id,
            "status": status,
            "confidence": round(float(confidence), 2),
            "cve": cve or "",
            "cwe": cwe or "",
            "severity": severity.lower(),
            "evidence": evidence,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "execution_status": execution_status,
        }

    def cleanup(self, context: Dict[str, Any]) -> bool:
        """Ensure temporary files, background probes, or connections are cleanly terminated."""
        return True

    @abc.abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """Describe supported test levels, protocols, and audit features."""
        raise NotImplementedError

    def _run_cmd_safe(self, cmd: List[str], timeout: int = 15) -> tuple[int, str, str]:
        """Safely run command with subprocess."""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False
            )
            return proc.returncode, proc.stdout, proc.stderr
        except Exception as e:
            logger.debug(f"[{self.tool_id}] Subprocess execution error: {e}")
            return -1, "", str(e)
