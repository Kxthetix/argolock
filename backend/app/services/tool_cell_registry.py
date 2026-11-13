"""
Tool Cell Registry and Manifest Definitions for ARGOLOCK NET.
Defines versioned, pinned manifests for each of the 10 inventory tools.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from app.models.tool_cell_models import (
    ToolCellManifest, RiskApprovalClass, TargetKind
)


class ToolCellRegistry:
    """Registry maintaining versioned manifests for all isolated tool cells."""

    def __init__(self):
        self._manifests: Dict[str, ToolCellManifest] = {}
        self._register_default_manifests()

    def _register_default_manifests(self):
        # 01. Subfinder Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="subfinder",
                tool_name="ProjectDiscovery Subfinder",
                tool_version="v2.6.6",
                adapter_version="1.0.0",
                image_digest="sha256:subfinder-2.6.6-distroless-pinned",
                risk_class=RiskApprovalClass.PASSIVE,
                allowed_profiles=["passive", "ct_only", "dns_archive"],
                target_types=[TargetKind.DOMAIN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": False,
                    "allowed_protocols": ["https", "dns"],
                    "description": "Passive third-party OSINT and DNS resolvers only"
                },
                resource_limits={"memory_mb": 256, "cpus": 1.0, "timeout_seconds": 60},
                rate_limit_per_second=10.0,
                concurrency_limit=2,
                raw_evidence_policy={"format": "jsonl", "sha256_hash": True, "max_size_bytes": 5242880, "quarantine_on_invalid": True},
                paired_ai_role="subfinder_candidate_summarizer",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 02. Amass Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="amass",
                tool_name="OWASP Amass",
                tool_version="v4.2.0",
                adapter_version="1.0.0",
                image_digest="sha256:amass-4.2.0-alpine-pinned",
                risk_class=RiskApprovalClass.PASSIVE,
                allowed_profiles=["passive"],
                target_types=[TargetKind.DOMAIN, TargetKind.FQDN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": False,
                    "allowed_protocols": ["https", "dns"],
                    "description": "Passive OSINT sources only; active modes strictly barred"
                },
                resource_limits={"memory_mb": 512, "cpus": 1.0, "timeout_seconds": 90},
                rate_limit_per_second=5.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "json", "sha256_hash": True, "max_size_bytes": 10485760, "quarantine_on_invalid": True},
                paired_ai_role="amass_osint_analyst",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 03. Naabu Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="naabu",
                tool_name="ProjectDiscovery Naabu",
                tool_version="v2.3.1",
                adapter_version="1.0.0",
                image_digest="sha256:naabu-2.3.1-distroless-pinned",
                risk_class=RiskApprovalClass.LOW_IMPACT_ACTIVE,
                allowed_profiles=["top_100_tcp", "top_1000_tcp"],
                target_types=[TargetKind.IP, TargetKind.FQDN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["tcp", "syn"],
                    "description": "Restricted exclusively to ApprovedTargetSet resolved IPs and allowed ports"
                },
                resource_limits={"memory_mb": 256, "cpus": 1.0, "timeout_seconds": 120},
                rate_limit_per_second=100.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "jsonl", "sha256_hash": True, "max_size_bytes": 5242880, "quarantine_on_invalid": True},
                paired_ai_role="naabu_port_analyst",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 04. Nmap Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="nmap",
                tool_name="Nmap Security Scanner",
                tool_version="7.94",
                adapter_version="1.0.0",
                image_digest="sha256:nmap-7.94-alpine-pinned",
                risk_class=RiskApprovalClass.LOW_IMPACT_ACTIVE,
                allowed_profiles=["service_light", "version_probes"],
                target_types=[TargetKind.HOST_PORT, TargetKind.IP],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["tcp"],
                    "description": "Probes directed only to known open ports from Naabu"
                },
                resource_limits={"memory_mb": 512, "cpus": 1.0, "timeout_seconds": 120},
                rate_limit_per_second=20.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "xml", "sha256_hash": True, "max_size_bytes": 10485760, "quarantine_on_invalid": True},
                paired_ai_role="nmap_service_fingerprinter",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 05. httpx_probe Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="httpx_probe",
                tool_name="HTTPX Probing Adapter (ProjectDiscovery httpx wrapper)",
                tool_version="v1.6.8",
                adapter_version="1.0.0",
                image_digest="sha256:httpx-1.6.8-distroless-pinned",
                risk_class=RiskApprovalClass.LOW_IMPACT_ACTIVE,
                allowed_profiles=["standard_probe", "tech_detect_only"],
                target_types=[TargetKind.HOST_PORT, TargetKind.WEB_ORIGIN, TargetKind.FQDN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["http", "https"],
                    "description": "HTTP/HTTPS probes to approved endpoints; external redirects blocked"
                },
                resource_limits={"memory_mb": 256, "cpus": 1.0, "timeout_seconds": 60},
                rate_limit_per_second=15.0,
                concurrency_limit=2,
                raw_evidence_policy={"format": "jsonl", "sha256_hash": True, "max_size_bytes": 5242880, "quarantine_on_invalid": True},
                paired_ai_role="httpx_origin_triager",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 06. WhatWeb Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="whatweb",
                tool_name="WhatWeb NextGen Web Scanner",
                tool_version="0.5.5",
                adapter_version="1.0.0",
                image_digest="sha256:whatweb-0.5.5-ruby-pinned",
                risk_class=RiskApprovalClass.LOW_IMPACT_ACTIVE,
                allowed_profiles=["conservative_stealth", "standard"],
                target_types=[TargetKind.WEB_ORIGIN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["http", "https"],
                    "description": "Passive and conservative technology header/fingerprint probing"
                },
                resource_limits={"memory_mb": 256, "cpus": 1.0, "timeout_seconds": 60},
                rate_limit_per_second=10.0,
                concurrency_limit=2,
                raw_evidence_policy={"format": "json", "sha256_hash": True, "max_size_bytes": 5242880, "quarantine_on_invalid": True},
                paired_ai_role="whatweb_tech_analyst",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 07. Nuclei Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="nuclei",
                tool_name="ProjectDiscovery Nuclei",
                tool_version="v3.2.9",
                adapter_version="1.0.0",
                image_digest="sha256:nuclei-3.2.9-distroless-pinned",
                risk_class=RiskApprovalClass.VALIDATION,
                allowed_profiles=["curated_network", "curated_web"],
                target_types=[TargetKind.HOST_PORT, TargetKind.WEB_ORIGIN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["tcp", "http", "https"],
                    "description": "Egress strictly bound to approved origins/endpoints; no OAST external callbacks without approval"
                },
                resource_limits={"memory_mb": 512, "cpus": 1.0, "timeout_seconds": 120},
                rate_limit_per_second=25.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "jsonl", "sha256_hash": True, "max_size_bytes": 10485760, "quarantine_on_invalid": True},
                paired_ai_role="nuclei_match_explainer",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 08. ZAP Passive Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="zap_passive",
                tool_name="OWASP ZAP (Crawl & Passive Rules)",
                tool_version="2.14.0",
                adapter_version="1.0.0",
                image_digest="sha256:zap-2.14.0-stable-pinned",
                risk_class=RiskApprovalClass.PASSIVE,
                allowed_profiles=["crawl_and_passive_rules"],
                target_types=[TargetKind.WEB_ORIGIN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["http", "https"],
                    "description": "Crawl within in-scope origin; logout and state-changing endpoints excluded"
                },
                resource_limits={"memory_mb": 1024, "cpus": 1.0, "timeout_seconds": 180},
                rate_limit_per_second=15.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "json", "sha256_hash": True, "max_size_bytes": 20971520, "quarantine_on_invalid": True},
                paired_ai_role="zap_route_analyst",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 09. Nikto Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="nikto",
                tool_name="Nikto Web Server Scanner",
                tool_version="2.5.0",
                adapter_version="1.0.0",
                image_digest="sha256:nikto-2.5.0-perl-pinned",
                risk_class=RiskApprovalClass.VALIDATION,
                allowed_profiles=["server_misconfig_safe"],
                target_types=[TargetKind.WEB_ORIGIN],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["http", "https"],
                    "description": "Targeted HTTP requests for server configuration errors"
                },
                resource_limits={"memory_mb": 256, "cpus": 1.0, "timeout_seconds": 90},
                rate_limit_per_second=10.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "json", "sha256_hash": True, "max_size_bytes": 5242880, "quarantine_on_invalid": True},
                paired_ai_role="nikto_server_analyst",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 10. Dalfox Cell Manifest
        self.register(
            ToolCellManifest(
                tool_id="dalfox",
                tool_name="Dalfox Parameter XSS Scanner",
                tool_version="v2.9.2",
                adapter_version="1.0.0",
                image_digest="sha256:dalfox-2.9.2-distroless-pinned",
                risk_class=RiskApprovalClass.OPERATOR_APPROVED,
                allowed_profiles=["candidate_parameter_xss"],
                target_types=[TargetKind.URL],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["http", "https"],
                    "description": "Active injection payloads against pre-approved parameter targets only"
                },
                resource_limits={"memory_mb": 256, "cpus": 1.0, "timeout_seconds": 90},
                rate_limit_per_second=5.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "json", "sha256_hash": True, "max_size_bytes": 5242880, "quarantine_on_invalid": True},
                paired_ai_role="dalfox_xss_analyst",
                paired_ai_profile_version="1.0.0",
            )
        )

        # 11. ZAP Active Cell Manifest (Separately Approved Stage)
        self.register(
            ToolCellManifest(
                tool_id="zap_active",
                tool_name="OWASP ZAP (Active Attack Policy)",
                tool_version="2.14.0",
                adapter_version="1.0.0",
                image_digest="sha256:zap-2.14.0-stable-pinned",
                risk_class=RiskApprovalClass.OPERATOR_APPROVED,
                allowed_profiles=["active_scan_approved"],
                target_types=[TargetKind.WEB_ORIGIN, TargetKind.URL],
                network_egress_policy={
                    "default_deny": True,
                    "restrict_to_targets": True,
                    "allowed_protocols": ["http", "https"],
                    "description": "Active web application attacks; requires separate operator approval token"
                },
                resource_limits={"memory_mb": 1024, "cpus": 1.0, "timeout_seconds": 180},
                rate_limit_per_second=10.0,
                concurrency_limit=1,
                raw_evidence_policy={"format": "json", "sha256_hash": True, "max_size_bytes": 20971520, "quarantine_on_invalid": True},
                paired_ai_role="zap_active_analyst",
                paired_ai_profile_version="1.0.0",
            )
        )

    def register(self, manifest: ToolCellManifest) -> None:
        self._manifests[manifest.tool_id] = manifest

    def get_manifest(self, tool_id: str) -> Optional[ToolCellManifest]:
        return self._manifests.get(tool_id)

    def list_manifests(self) -> List[ToolCellManifest]:
        return list(self._manifests.values())


# Global singleton instance
tool_cell_registry = ToolCellRegistry()
