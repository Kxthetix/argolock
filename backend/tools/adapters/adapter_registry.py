"""Tool Adapter Registry and Health Monitoring for ARGOLOCK NET v1.6."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from loguru import logger

from tools.adapters.base_adapter import ToolAdapter
from tools.adapters.nmap_adapter import NmapAdapter
from tools.adapters.nuclei_adapter import NucleiAdapter
from tools.adapters.sqlmap_adapter import SQLMapAdapter
from tools.adapters.burp_zap_adapter import BurpZapAdapter
from tools.adapters.searchsploit_adapter import SearchSploitAdapter
from tools.adapters.windows_ad_adapter import WindowsADAdapter
from tools.adapters.cloud_container_adapter import CloudContainerAdapter


class ToolAdapterRegistry:
    """Central registry for discovering, selecting, and health-checking tool adapters."""

    def __init__(self):
        self._adapters: Dict[str, ToolAdapter] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register_adapter(NmapAdapter())
        self.register_adapter(NucleiAdapter())
        self.register_adapter(SQLMapAdapter())
        self.register_adapter(BurpZapAdapter())
        self.register_adapter(SearchSploitAdapter())
        self.register_adapter(WindowsADAdapter())
        self.register_adapter(CloudContainerAdapter())

    def register_adapter(self, adapter: ToolAdapter) -> None:
        self._adapters[adapter.tool_id] = adapter
        logger.debug(f"[ToolRegistry] Registered adapter: {adapter.tool_id} ({adapter.name})")

    def get_adapter(self, tool_id: str) -> Optional[ToolAdapter]:
        return self._adapters.get(tool_id)

    def list_adapters(self) -> List[ToolAdapter]:
        return list(self._adapters.values())

    def get_all_health_statuses(self) -> List[Dict[str, Any]]:
        """Run health check across all registered tool adapters."""
        statuses = []
        for adapter in self._adapters.values():
            try:
                report = adapter.health_check()
                statuses.append(report)
            except Exception as e:
                logger.error(f"[ToolRegistry] Health check failed for {adapter.tool_id}: {e}")
                statuses.append({
                    "tool_id": adapter.tool_id,
                    "name": adapter.name,
                    "category": adapter.category,
                    "installed": False,
                    "version": "error",
                    "configuration_valid": False,
                    "health_status": "ERROR",
                    "error": str(e),
                })
        return statuses

    def find_adapter_for_vulnerability(
        self,
        vulnerability_type: str,
        protocol: str = "http",
        cve: Optional[str] = None
    ) -> Optional[ToolAdapter]:
        """Select the best matching adapter for a finding based on category and metadata."""
        vuln_lower = vulnerability_type.lower()
        if "sql" in vuln_lower or "injection" in vuln_lower and "sql" in vuln_lower:
            return self.get_adapter("sqlmap")
        if "template" in vuln_lower or "cve" in vuln_lower or cve:
            return self.get_adapter("nuclei")
        if "smb" in vuln_lower or "active directory" in vuln_lower or "ldap" in vuln_lower or "kerberos" in vuln_lower:
            return self.get_adapter("windows_ad")
        if "port" in vuln_lower or "service" in vuln_lower or protocol in ("tcp", "udp"):
            return self.get_adapter("nmap")
        if "cloud" in vuln_lower or "container" in vuln_lower or "s3" in vuln_lower:
            return self.get_adapter("cloud_container")
        # Default web/API adapter
        return self.get_adapter("burp_zap")


adapter_registry = ToolAdapterRegistry()
