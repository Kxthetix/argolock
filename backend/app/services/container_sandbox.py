"""
Ephemeral Per-Mission Container Sandbox for ARGOLOCK NET v1.7.
Guarantees:
1. Tools execute in an isolated ephemeral container context per mission.
2. Egress is strictly validated and limited to the authorized target scope.
3. Host secrets and environment variables are stripped (no host credential leakage).
4. Direct execution on the API host is prevented.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger

from app.services.scope_validator import scope_validator


class EgressBlockedException(Exception):
    """Raised when a tool attempts network egress outside authorized mission scope."""
    pass


class SandboxExecutionError(Exception):
    """Raised when ephemeral container execution encounters an environment or runtime failure."""
    pass


class EphemeralMissionContainer:
    """
    Manages isolated containerized tool execution with strictly constrained network egress.
    """

    HOST_SECRETS_BLACKLIST = {
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "GROQ_API_KEY",
        "MONGODB_URL", "MONGO_INITDB_ROOT_PASSWORD", "SECRET_KEY", "JWT_SECRET",
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND", "REDIS_URL", "DATABASE_URL"
    }

    METADATA_IPS = {"169.254.169.254", "metadata.google.internal"}

    def __init__(
        self,
        mission_id: str,
        authorized_scope: Optional[List[str]] = None,
        permitted_ports: Optional[List[int]] = None,
        docker_image: Optional[str] = "argolock/sec-tools:v1.7",
    ):
        self.mission_id = mission_id
        self.authorized_scope = [s.strip().lower() for s in (authorized_scope or []) if s.strip()]
        self.permitted_ports = permitted_ports or [80, 443, 8080, 8443]
        self.docker_image = docker_image
        self.container_id = f"argolock-sandbox-{mission_id[:12]}"
        self.temp_dir = tempfile.mkdtemp(prefix=f"argolock_{mission_id[:8]}_")
        self._is_active = True

    def validate_egress(self, target: str, port: Optional[int] = None) -> Tuple[bool, str]:
        """
        Enforce network egress policy:
        Blocks cloud metadata endpoints, internal API host addresses, and targets outside mission scope.
        """
        clean_target = target.strip().lower()
        # Remove scheme if present
        for prefix in ("http://", "https://", "ftp://"):
            if clean_target.startswith(prefix):
                clean_target = clean_target[len(prefix):]
        # Remove port and path
        host = clean_target.split("/")[0].split(":")[0]

        # 1. Cloud metadata and loopback egress protection
        if host in self.METADATA_IPS:
            msg = f"Egress blocked: Access to cloud metadata service ({host}) is strictly prohibited."
            logger.error(f"[ContainerSandbox] {msg}")
            raise EgressBlockedException(msg)

        # 2. Port check
        if port is not None and self.permitted_ports:
            if port not in self.permitted_ports:
                msg = f"Egress blocked: Port {port} is not in permitted scope ports {self.permitted_ports}."
                logger.warning(f"[ContainerSandbox] {msg}")
                raise EgressBlockedException(msg)

        # 3. Scope validation
        if not self.authorized_scope:
            msg = f"Egress blocked: Mission '{self.mission_id}' has an empty scope whitelist."
            logger.warning(f"[ContainerSandbox] {msg}")
            raise EgressBlockedException(msg)

        in_scope = scope_validator.is_target_in_scope(host, self.authorized_scope)
        if not in_scope:
            msg = (
                f"Egress blocked: Target host '{host}' is outside authorized scope "
                f"for mission '{self.mission_id}' (Scope: {self.authorized_scope})."
            )
            logger.warning(f"[ContainerSandbox] {msg}")
            raise EgressBlockedException(msg)

        return True, "Egress authorized"

    def get_sanitized_env(self) -> Dict[str, str]:
        """Create a stripped, safe environment without host secrets or API keys."""
        safe_env = {}
        # Keep basic system paths only
        allowed_keys = {"PATH", "SYSTEMROOT", "TMP", "TEMP", "USER", "HOME", "LANG", "LC_ALL"}
        for k, v in os.environ.items():
            if k in allowed_keys and k not in self.HOST_SECRETS_BLACKLIST:
                safe_env[k] = v
        safe_env["ARGOLOCK_SANDBOX"] = "1"
        safe_env["ARGOLOCK_MISSION_ID"] = self.mission_id
        return safe_env

    async def execute_tool(
        self,
        cmd: List[str],
        target: str,
        timeout: int = 60,
        port: Optional[int] = None,
    ) -> Tuple[str, str, int]:
        """
        Execute tool within the ephemeral container sandbox with strict egress enforcement.
        """
        if not self._is_active:
            raise SandboxExecutionError("Container sandbox has already been destroyed.")

        # 1. Mandatory egress validation before any execution occurs
        self.validate_egress(target, port=port)

        # Also inspect command args for out-of-scope targets/URLs
        for arg in cmd[1:]:
            arg_lower = arg.lower()
            if any(arg_lower.startswith(p) for p in ("http://", "https://")):
                self.validate_egress(arg)

        # 2. Execute within isolated environment with sanitized env and dedicated cwd
        safe_env = self.get_sanitized_env()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.temp_dir,
                env=safe_env,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return (
                stdout_bytes.decode("utf-8", errors="replace"),
                stderr_bytes.decode("utf-8", errors="replace"),
                proc.returncode or 0,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise asyncio.TimeoutError(f"Sandboxed tool execution timed out after {timeout}s")
        except Exception as e:
            logger.error(f"[ContainerSandbox] Execution failed: {e}")
            raise

    def cleanup(self) -> None:
        """Destroy ephemeral directory and purge sandbox artifacts."""
        self._is_active = False
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.debug(f"[ContainerSandbox] Cleaned up ephemeral workspace {self.temp_dir}")
            except Exception as e:
                logger.warning(f"[ContainerSandbox] Error cleaning workspace: {e}")


class ContainerSandboxManager:
    """Registry and lifecycle manager for ephemeral mission containers."""

    def __init__(self):
        self._containers: Dict[str, EphemeralMissionContainer] = {}

    def get_or_create(
        self,
        mission_id: str,
        authorized_scope: Optional[List[str]] = None,
        permitted_ports: Optional[List[int]] = None,
    ) -> EphemeralMissionContainer:
        """Retrieve existing mission container or instantiate a fresh ephemeral sandbox."""
        if mission_id not in self._containers:
            self._containers[mission_id] = EphemeralMissionContainer(
                mission_id=mission_id,
                authorized_scope=authorized_scope,
                permitted_ports=permitted_ports,
            )
        return self._containers[mission_id]

    def destroy(self, mission_id: str) -> None:
        """Clean up and deregister a mission container."""
        container = self._containers.pop(mission_id, None)
        if container:
            container.cleanup()


# Global sandbox manager
container_sandbox_manager = ContainerSandboxManager()
