"""Base tool runner — executes security tools via Docker or subprocess.

If a tool binary is not found on the host system (subprocess mode), the tool
subclass may implement ``fallback_run`` to perform a real Python-based probe
against the target, avoiding a hard FAILED status.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import shlex
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from app.config import settings
from app.models.scan import ToolResult, ToolStatus


class ToolExecutionError(Exception):
    pass


class BaseTool(ABC):
    """Abstract base for all security tool integrations."""

    name: str = "base_tool"
    docker_image: Optional[str] = None

    def __init__(self):
        self.execution_mode = settings.tool_execution_mode
        self.timeout = settings.tool_timeout_seconds

    @abstractmethod
    def build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Build the command to run (as a list of args)."""
        ...

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, target: str) -> Dict[str, Any]:
        """Parse raw tool output into structured JSON data."""
        ...

    def fallback_run(self, target: str, options: Dict[str, Any]) -> Optional[Tuple[str, str, int]]:
        """Optional Python-based fallback when the binary is missing.

        Subclasses should override this to return (stdout, stderr, exit_code)
        based on a real network probe of the target. Return None to raise a
        missing-binary error as usual.
        """
        return None

    def _should_fallback(self, stdout: str, stderr: str, exit_code: int) -> bool:
        """Check if the command execution output indicates a permission failure or binary block."""
        if self.name == "nmap":
            # Check for raw socket or operation permission error
            if "Couldn't open a raw socket" in stdout or "Couldn't open a raw socket" in stderr:
                return True
            if "Operation not permitted" in stdout or "Operation not permitted" in stderr:
                return True
            # Check if host discovery blocked
            if "0 IP addresses (0 hosts up) scanned" in stdout:
                return True
        elif self.name == "naabu":
            # If naabu exited with error or returned 0 ports when it had an error
            if exit_code not in (0, 1):
                return True
        return False

    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """Execute the tool and return a structured ToolResult."""
        options = options or {}
        result = ToolResult(
            tool_name=self.name,
            status=ToolStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        stdout, stderr, exit_code = "", "", 0
        try:
            if self.execution_mode == "docker" and self.docker_image:
                try:
                    stdout, stderr, exit_code = await self._run_docker(target, options)
                    if self._should_fallback(stdout, stderr, exit_code):
                        fallback_result = self.fallback_run(target, options)
                        if fallback_result is not None:
                            logger.warning(f"[{self.name}] Docker execution blocked/failed. Running Python fallback probe.")
                            stdout, stderr, exit_code = fallback_result
                except Exception as docker_exc:
                    fallback_result = self.fallback_run(target, options)
                    if fallback_result is not None:
                        logger.warning(f"[{self.name}] Docker execution error: {docker_exc}. Running Python fallback probe.")
                        stdout, stderr, exit_code = fallback_result
                    else:
                        raise
            else:
                # Detect if binary is missing before launching subprocess
                cmd = self.build_command(target, options)
                binary = cmd[0] if cmd else ""
                binary_found = shutil.which(binary) is not None

                if not binary_found:
                    # Try Python fallback first
                    fallback_result = self.fallback_run(target, options)
                    if fallback_result is not None:
                        logger.warning(
                            f"[{self.name}] Binary '{binary}' not found. "
                            f"Running Python fallback probe."
                        )
                        stdout, stderr, exit_code = fallback_result
                    else:
                        raise FileNotFoundError(
                            f"Tool '{binary}' not found in PATH and no fallback is implemented."
                        )
                else:
                    try:
                        stdout, stderr, exit_code = await self._run_subprocess(target, options)
                        if self._should_fallback(stdout, stderr, exit_code):
                            fallback_result = self.fallback_run(target, options)
                            if fallback_result is not None:
                                logger.warning(f"[{self.name}] Subprocess execution blocked/failed (exit_code={exit_code}). Running Python fallback probe.")
                                stdout, stderr, exit_code = fallback_result
                    except Exception as sub_exc:
                        fallback_result = self.fallback_run(target, options)
                        if fallback_result is not None:
                            logger.warning(f"[{self.name}] Subprocess execution error: {sub_exc}. Running Python fallback probe.")
                            stdout, stderr, exit_code = fallback_result
                        else:
                            raise

            result.raw_output = stdout[:50000]  # Cap raw output
            result.exit_code = exit_code

            if exit_code not in (0, 1):  # Some tools return 1 on findings
                logger.warning(f"{self.name} exited with code {exit_code}: {stderr[:500]}")

            result.parsed_data = self.parse_output(stdout, stderr, target)
            result.status = ToolStatus.COMPLETED

        except asyncio.TimeoutError:
            result.status = ToolStatus.FAILED
            result.error = f"Tool timed out after {self.timeout}s"
            logger.error(f"{self.name} timed out for target {target}")
        except Exception as exc:
            result.status = ToolStatus.FAILED
            result.error = str(exc)
            logger.error(f"{self.name} failed for {target}: {exc}")

        result.completed_at = datetime.utcnow()
        if result.started_at:
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def _run_docker(
        self, target: str, options: Dict[str, Any]
    ) -> tuple[str, str, int]:
        """Run tool inside a Docker container."""
        tool_cmd = self.build_command(target, options)
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "host",
            "--memory", "512m",
            "--cpus", "1.0",
            self.docker_image,
        ] + tool_cmd

        logger.debug(f"[{self.name}] Docker command: {' '.join(docker_cmd)}")
        return await self._execute(docker_cmd)

    async def _run_subprocess(
        self, target: str, options: Dict[str, Any]
    ) -> tuple[str, str, int]:
        """Run tool directly as a subprocess."""
        cmd = self.build_command(target, options)
        logger.debug(f"[{self.name}] Subprocess command: {' '.join(cmd)}")
        return await self._execute(cmd)

    async def _execute(self, cmd: List[str]) -> tuple[str, str, int]:
        """Execute a command asynchronously with timeout."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise

        return (
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            proc.returncode or 0,
        )
