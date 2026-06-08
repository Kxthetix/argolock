"""Scope validator — ensures scan targets are user-owned or authorized."""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse

from loguru import logger


# ── Private IP ranges that should never be scanned unless explicitly allowed ──
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# ── Safe test targets (always allowed for demo/testing) ───────────────────────
SAFE_TEST_TARGETS = {
    "scanme.nmap.org",
    "testphp.vulnweb.com",
    "demo.testfire.net",
    "juice-shop.herokuapp.com",
}

# ── Cloud metadata endpoints — must never be accessed ────────────────────────
BLOCKED_TARGETS = {
    "169.254.169.254",   # AWS/GCP/Azure metadata
    "metadata.google.internal",
}


def normalize_target(target: str) -> str:
    """Strip protocol and trailing slash from target."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc or parsed.path
    return target.strip().rstrip("/")


def is_ip_address(target: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        return None


def is_ip_network(target: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None


def validate_domain(domain: str) -> bool:
    """Basic domain format validation."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


async def validate_scope(target: str, authorized: bool) -> tuple[bool, str]:
    """
    Validate that a target is safe to scan.

    Returns:
        (is_valid: bool, reason: str)
    """
    if not authorized:
        return False, "User did not confirm authorization to scan this target."

    normalized = normalize_target(target)

    # Block metadata endpoints
    if normalized in BLOCKED_TARGETS:
        return False, f"Target '{normalized}' is a blocked cloud metadata endpoint."

    # Check if it's an IP
    ip = is_ip_address(normalized)
    if ip:
        for private_range in PRIVATE_RANGES:
            if ip in private_range:
                logger.warning(f"Scan attempt on private IP {normalized} — allowed (internal scan)")
                # Allow internal IPs — user may be scanning their own infra
                return True, f"Private IP {normalized} — authorized internal scan."
        return True, f"Public IP {normalized} — authorized."

    # Check if it's a CIDR range
    network = is_ip_network(normalized)
    if network:
        if network.num_addresses > 256:
            return False, f"Network range too large ({network.num_addresses} hosts). Max 256 (/24)."
        return True, f"CIDR range {normalized} — authorized."

    # It's a domain
    if not validate_domain(normalized):
        return False, f"'{normalized}' is not a valid domain name or IP address."

    # Safe test targets
    if normalized in SAFE_TEST_TARGETS or any(normalized.endswith(f".{t}") for t in SAFE_TEST_TARGETS):
        return True, f"'{normalized}' is a known safe test target."

    # Domain is valid — we trust the authorization flag
    return True, f"Domain '{normalized}' — user authorized scan."
