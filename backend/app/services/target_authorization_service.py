"""Target Authorization Service for ARGOLOCK NET v1.6.

Guarantees that all VAPT operations target only strictly approved, owned,
and scoped infrastructure within declared testing windows.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger

from app.models.vapt_models import TargetAuthorization, AuthorizationStatus, TestingMode
from app.services.scope_validator import normalize_target, is_ip_address, is_ip_network


async def _maybe_await(val):
    import asyncio
    if asyncio.iscoroutine(val) or hasattr(val, "__await__"):
        return await val
    return val


class TargetAuthorizationService:
    """Manages explicit target asset authorization records and scope policies."""

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        try:
            from app.database import get_db
            return get_db()
        except Exception:
            from workers.recon_worker import _get_db_sync
            return _get_db_sync()

    async def create_authorization(self, auth: TargetAuthorization) -> TargetAuthorization:
        """Register a new authorized target."""
        db = self._get_db()
        doc = auth.model_dump()
        await _maybe_await(db["target_authorizations"].update_one(
            {"asset_id": auth.asset_id},
            {"$set": doc},
            upsert=True
        ))
        logger.info(f"[TargetAuth] Authorized asset {auth.asset_id} ({auth.hostname_or_ip}) for {auth.owner}")
        return auth

    async def get_authorization_by_asset(self, asset_id: str) -> Optional[TargetAuthorization]:
        """Fetch authorization record by asset_id."""
        db = self._get_db()
        doc = await _maybe_await(db["target_authorizations"].find_one({"asset_id": asset_id}, {"_id": 0}))
        if not doc:
            return None
        return TargetAuthorization(**doc)

    async def get_authorization_by_target(self, target: str) -> Optional[TargetAuthorization]:
        """Find matching authorization record for a target hostname or IP."""
        db = self._get_db()
        norm_target = normalize_target(target)
        
        # Check safe test targets (always authorized benchmarks)
        from app.services.scope_validator import SAFE_TEST_TARGETS
        if norm_target in SAFE_TEST_TARGETS or any(norm_target.endswith(f".{t}") for t in SAFE_TEST_TARGETS):
            return TargetAuthorization(
                asset_id=f"asset-bench-{norm_target.replace('.', '-')}",
                hostname_or_ip=norm_target,
                owner="Authorized Benchmark Target",
                authorization_status=AuthorizationStatus.AUTHORIZED,
                scope=[norm_target],
                permitted_ports=[21, 22, 80, 443, 8080],
                permitted_services=["http", "https", "ssh", "ftp"],
                testing_mode=TestingMode.CONTROLLED_PROOF,
                assessment_id="benchmark-vapt",
                approval_reference="BENCHMARK-SAFE-TARGET",
                ownership_proof_type="benchmark_preauthorized",
                ownership_verified=True,
                intensity="safe",
            )

        # Direct match
        doc = await _maybe_await(db["target_authorizations"].find_one(
            {"hostname_or_ip": norm_target, "authorization_status": AuthorizationStatus.AUTHORIZED.value},
            {"_id": 0}
        ))
        if doc and isinstance(doc, dict) and "asset_id" in doc:
            return TargetAuthorization(**doc)

        # Check in scope entries
        cursor = db["target_authorizations"].find(
            {"authorization_status": AuthorizationStatus.AUTHORIZED.value},
            {"_id": 0}
        )
        if hasattr(cursor, "to_list"):
            all_auths = await cursor.to_list(length=500)
        else:
            all_auths = list(cursor.limit(500) if hasattr(cursor, "limit") else cursor)
        target_ip = is_ip_address(norm_target)

        for a in all_auths:
            auth_model = TargetAuthorization(**a)
            for sc in auth_model.scope:
                sc_norm = normalize_target(sc)
                if sc_norm == norm_target:
                    return auth_model
                # Check CIDR match if target is an IP
                if target_ip:
                    net = is_ip_network(sc_norm)
                    if net and target_ip in net:
                        return auth_model
                # Subdomain match
                if not target_ip and (norm_target == sc_norm or norm_target.endswith(f".{sc_norm}")):
                    return auth_model

        return None

    async def verify_target_ownership(
        self,
        target: str,
        proof_type: str,
        expected_token: str
    ) -> Tuple[bool, str]:
        """Verify target ownership via DNS TXT or well-known challenge token."""
        norm = normalize_target(target)
        from app.services.scope_validator import SAFE_TEST_TARGETS
        if norm in SAFE_TEST_TARGETS or any(norm.endswith(f".{t}") for t in SAFE_TEST_TARGETS):
            return True, f"Benchmark target {norm} is pre-authorized"

        if proof_type == "dns_txt":
            from workers.exploit_worker import get_txt_records
            records = get_txt_records(norm)
            for rec in records:
                if expected_token in rec or f"argolock-site-verification={expected_token}" in rec:
                    return True, f"DNS TXT ownership proof verified on {norm}"
            return False, f"DNS TXT token '{expected_token}' not found on {norm}"

        elif proof_type == "well_known_file":
            import httpx
            url = f"http://{norm}/.well-known/argolock-challenge"
            try:
                async with httpx.AsyncClient(timeout=4.0, verify=False) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200 and expected_token in resp.text:
                        return True, f"Well-known file token verified at {url}"
            except Exception as e:
                logger.debug(f"Well-known token check failed for {url}: {e}")
            return False, f"Well-known challenge file at {url} did not match token"

        return False, f"Unknown ownership proof type: {proof_type}"

    async def list_authorizations(self, limit: int = 100) -> List[TargetAuthorization]:
        db = self._get_db()
        cursor = db["target_authorizations"].find({}, {"_id": 0}).limit(limit)
        if hasattr(cursor, "to_list"):
            docs = await cursor.to_list(length=limit)
        else:
            docs = list(cursor)
        return [TargetAuthorization(**d) for d in docs]

    async def verify_target_authorization(
        self,
        target: str,
        port: Optional[int] = None,
        service: Optional[str] = None
    ) -> Tuple[bool, str, Optional[TargetAuthorization]]:
        """
        Hard authorization gate check.
        Returns: (is_authorized: bool, reason: str, auth_record: Optional[TargetAuthorization])
        """
        auth = await self.get_authorization_by_target(target)
        if not auth:
            return False, f"BLOCK: Target '{target}' is not registered in ARGOLOCK asset authorization inventory.", None

        if auth.authorization_status != AuthorizationStatus.AUTHORIZED:
            return False, f"BLOCK: Asset '{auth.asset_id}' authorization status is {auth.authorization_status.value.upper()}.", auth

        # Verify target ownership proof
        if not auth.ownership_verified:
            return False, f"BLOCK: Target '{target}' ownership proof (DNS TXT or well-known token) is unverified.", auth

        # Verify testing window
        now = datetime.now(timezone.utc)
        if auth.testing_window_start and now < auth.testing_window_start:
            return False, f"BLOCK: Testing window for asset '{auth.asset_id}' has not started yet.", auth
        if auth.testing_window_end and now > auth.testing_window_end:
            return False, f"BLOCK: Testing window for asset '{auth.asset_id}' expired at {auth.testing_window_end.isoformat()}.", auth

        # Verify port if specified
        if port is not None and auth.permitted_ports:
            if port not in auth.permitted_ports:
                return False, f"BLOCK: Port {port} is not in permitted ports {auth.permitted_ports} for asset '{auth.asset_id}'.", auth

        # Verify service if specified
        if service and auth.permitted_services:
            if service.lower() not in [s.lower() for s in auth.permitted_services]:
                return False, f"BLOCK: Service '{service}' is not permitted for asset '{auth.asset_id}'.", auth

        return True, "Authorized and scoped.", auth


target_auth_service = TargetAuthorizationService()
