"""
Scope Resolver & Boundary Enforcement Service for ARGOLOCK NET.
Enforces:
1. DNS resolution and comparison against approved roots/IP ranges.
2. Exclusion list filtering.
3. CDN and shared-hosting detection (holding ambiguous ownership out of active scans).
4. Generation of immutable ApprovedTargetSet records.
5. Immediate pre-dispatch scope recheck.
6. Safe redirect validation (external origins never expand scope).
"""
from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from loguru import logger

from app.models.tool_cell_models import (
    ApprovedTargetSet, TargetKind, ScopeAllowDecision, DomainCandidate, WebOrigin
)
from app.services.scope_validator import normalize_target, is_ip_address, is_ip_network, SAFE_TEST_TARGETS


# Known CDN / Cloud Shared Edge Autonomous Systems & Domains
KNOWN_CDN_CNAMES = [
    "cloudflare.net", "cloudfront.net", "akamai.net", "akamaiedge.net",
    "fastly.net", "azureedge.net", "azurefd.net", "incapdns.net"
]

KNOWN_SHARED_EDGE_IPS = [
    # Common Cloudflare / CloudFront shared edge ranges (sample indicators)
    "104.16.0.0/12", "104.24.0.0/14", "172.64.0.0/13", "13.224.0.0/14"
]


class ScopeResolverService:
    """Resolves asset candidates, checks boundaries, and pins approved target sets."""

    def __init__(self, dns_resolver_fn=None):
        self._custom_dns_resolver = dns_resolver_fn

    def resolve_hostname(self, host: str) -> List[str]:
        """Resolve host to list of IP addresses."""
        if self._custom_dns_resolver:
            return self._custom_dns_resolver(host)
        if is_ip_address(host):
            return [host]
        try:
            # Look up host
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list({info[4][0] for info in infos})
            return sorted(ips)
        except Exception as e:
            logger.debug(f"[ScopeResolver] DNS resolution failed for {host}: {e}")
            return []

    def is_cdn_or_shared_hosting(self, host: str, ips: List[str], cname: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Identify if target points to a shared CDN edge where scanning requires caution."""
        if cname:
            cname_lower = cname.lower()
            for cdn_domain in KNOWN_CDN_CNAMES:
                if cdn_domain in cname_lower:
                    return True, f"CDN CNAME ({cdn_domain})"

        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for net_str in KNOWN_SHARED_EDGE_IPS:
                    if ip_obj in ipaddress.ip_network(net_str):
                        return True, f"Shared Edge IP block ({net_str})"
            except ValueError:
                pass

        return False, None

    def resolve_candidate_set(
        self,
        asset_id: str,
        scope_version: str,
        candidates: List[DomainCandidate],
        approved_roots: List[str],
        exclusions: List[str],
        hold_shared_cdn: bool = True,
    ) -> ApprovedTargetSet:
        """
        Evaluate discovered candidates against approved roots, exclusions, and shared hosting.
        Emits an ApprovedTargetSet with explicit allow/held/excluded decisions.
        """
        normalized_roots = [normalize_target(r).lower() for r in approved_roots]
        normalized_exclusions = [normalize_target(e).lower() for e in exclusions]

        approved_targets: List[str] = []
        resolved_ips: List[str] = []
        exclusions_applied: List[str] = []
        resolution_evidence: Dict[str, Any] = {}
        has_ambiguity = False
        shared_provider = None

        for cand in candidates:
            fqdn = cand.fqdn.strip().lower()
            norm_fqdn = normalize_target(fqdn)

            # 1. Check exclusions first
            is_excluded = False
            for excl in normalized_exclusions:
                if norm_fqdn == excl or norm_fqdn.endswith(f".{excl}"):
                    exclusions_applied.append(norm_fqdn)
                    is_excluded = True
                    break

            if is_excluded:
                continue

            # 2. Check in-scope root matching
            in_scope_root = False
            for root in normalized_roots:
                if norm_fqdn == root or norm_fqdn.endswith(f".{root}"):
                    in_scope_root = True
                    break

            # Benchmark safety check
            if not in_scope_root:
                for bench in SAFE_TEST_TARGETS:
                    if norm_fqdn == bench or norm_fqdn.endswith(f".{bench}"):
                        in_scope_root = True
                        break

            if not in_scope_root:
                # Discovered item outside approved roots is excluded automatically
                continue

            # 3. Resolve DNS
            ips = self.resolve_hostname(norm_fqdn)
            resolution_evidence[norm_fqdn] = {
                "resolved_ips": ips,
                "cname": cand.cname_target,
                "source_tool": cand.source_tool,
            }

            # 4. Shared CDN check
            is_cdn, provider = self.is_cdn_or_shared_hosting(norm_fqdn, ips, cand.cname_target)
            if is_cdn:
                shared_provider = provider
                if hold_shared_cdn:
                    has_ambiguity = True
                    resolution_evidence[norm_fqdn]["status"] = "HELD_FOR_REVIEW"
                    resolution_evidence[norm_fqdn]["reason"] = f"Points to {provider}"
                    continue

            approved_targets.append(norm_fqdn)
            resolved_ips.extend(ips)

        allow_decision = ScopeAllowDecision.ALLOWED
        if not approved_targets and has_ambiguity:
            allow_decision = ScopeAllowDecision.AMBIGUOUS_HELD

        return ApprovedTargetSet(
            asset_id=asset_id,
            scope_version=scope_version,
            targets=sorted(list(set(approved_targets))),
            target_kind=TargetKind.FQDN,
            allow_decision=allow_decision,
            resolution_evidence=resolution_evidence,
            resolved_ips=sorted(list(set(resolved_ips))),
            exclusions_applied=sorted(list(set(exclusions_applied))),
            is_cdn_or_shared=has_ambiguity,
            shared_provider=shared_provider,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )

    def revalidate_dispatch_scope(
        self,
        target: str,
        approved_target_set: ApprovedTargetSet,
        exclusions: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """
        Immediate pre-dispatch check ensuring target is actively within the pinned ApprovedTargetSet.
        """
        clean_target = normalize_target(target).lower()
        host = clean_target.split(":")[0] if ":" in clean_target else clean_target

        # Check exclusions
        exclusions = exclusions or []
        for excl in exclusions:
            norm_excl = normalize_target(excl).lower()
            if host == norm_excl or host.endswith(f".{norm_excl}"):
                return False, f"Target '{target}' matches exclusion '{excl}'"

        # Check if in pinned approved targets
        approved_hosts = {t.lower() for t in approved_target_set.targets}
        approved_ips = set(approved_target_set.resolved_ips)

        if host in approved_hosts:
            return True, "Target in approved target set"

        if host in approved_ips:
            return True, "Target IP in approved target set"

        # Safe benchmark fallback
        if host in SAFE_TEST_TARGETS or any(host.endswith(f".{s}") for s in SAFE_TEST_TARGETS):
            return True, "Target is an authorized safe benchmark"

        return False, f"Target '{target}' is not in the approved target set (scope version {approved_target_set.scope_version})"

    def validate_redirect_chain(
        self,
        initial_origin: str,
        redirect_urls: List[str],
        approved_target_set: ApprovedTargetSet,
    ) -> Tuple[List[str], bool, Optional[str]]:
        """
        Validate HTTP redirect hops.
        Stops chain as soon as an external/unapproved origin is encountered.
        Returns (safe_redirect_chain, had_external_hop, blocked_origin).
        """
        safe_chain: List[str] = [initial_origin]
        parsed_init = urlparse(initial_origin if "://" in initial_origin else f"http://{initial_origin}")
        approved_host = parsed_init.netloc.split(":")[0].lower()

        for url in redirect_urls:
            p = urlparse(url if "://" in url else f"http://{url}")
            hop_host = p.netloc.split(":")[0].lower()

            # Must be in approved target set
            valid, reason = self.revalidate_dispatch_scope(hop_host, approved_target_set)
            if not valid:
                logger.warning(f"[ScopeResolver] Redirect hop to '{hop_host}' is out of scope. Stopping redirect chain.")
                return safe_chain, True, hop_host

            safe_chain.append(url)

        return safe_chain, False, None


# Global singleton instance
scope_resolver = ScopeResolverService()
