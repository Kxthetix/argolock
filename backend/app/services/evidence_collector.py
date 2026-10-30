"""Evidence Collector with Redaction and SHA-256 Cryptographic Hashing for ARGOLOCK NET v1.6."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.vapt_models import EvidenceRecord


class EvidenceCollector:
    """Collects technical evidence with automated redaction and tamper-evident SHA-256 hashing."""

    SENSITIVE_PATTERNS = [
        (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*"), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"(?i)(authorization:\s*)[^\r\n]+"), r"\1[REDACTED_AUTH_HEADER]"),
        (re.compile(r"(?i)(password|passwd|pwd|secret|api_key|apikey|token)([\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+"), r"\1\2[REDACTED]"),
        (re.compile(r"(?i)(cookie:\s*)[^\r\n]+"), r"\1[REDACTED_COOKIE]"),
        (re.compile(r"(?i)(set-cookie:\s*)[^\r\n]+"), r"\1[REDACTED_COOKIE]"),
        (re.compile(r"(AKIA[0-9A-Z]{16})"), r"[REDACTED_AWS_KEY]"),
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), r"[REDACTED_PRIVATE_KEY]"),
        (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), r"[REDACTED_JWT]"),
        (re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]{10,}"), r"\1[REDACTED_BASIC_AUTH]"),
    ]

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        from app.database import get_db
        return get_db()

    def redact_sensitive_data(self, text: Optional[str]) -> tuple[Optional[str], List[str]]:
        """Mask credentials, tokens, and sensitive secrets."""
        if not text:
            return text, []

        redacted_fields = []
        result = text
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            if pattern.search(result):
                redacted_fields.append(pattern.pattern[:20])
                result = pattern.sub(replacement, result)

        return result, list(set(redacted_fields))

    def calculate_sha256(self, record_dict: Dict[str, Any]) -> str:
        """Generate deterministic SHA-256 hash of evidence content."""
        canonical_content = json.dumps(
            {
                "assessment_id": str(record_dict.get("assessment_id") or record_dict.get("finding_id") or ""),
                "asset": str(record_dict.get("asset") or record_dict.get("asset_id") or ""),
                "tool": str(record_dict.get("tool") or record_dict.get("tool_source") or ""),
                "tool_version": str(record_dict.get("tool_version") or ""),
                "request_excerpt": str(record_dict.get("request_excerpt") or record_dict.get("request_sample") or ""),
                "response_excerpt": str(record_dict.get("response_excerpt") or record_dict.get("response_sample") or ""),
                "method": str(record_dict.get("method") or record_dict.get("technique") or ""),
                "redaction_flag": bool(record_dict.get("redaction_flag") or record_dict.get("redacted_fields")),
                "banner_output": str(record_dict.get("banner_output") or ""),
                "config_snippet": str(record_dict.get("config_snippet") or ""),
            },
            sort_keys=True,
            default=str
        )
        return hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()

    def _prepare_evidence_record(
        self,
        finding_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        tool_source: Optional[str] = None,
        technique: Optional[str] = None,
        request_sample: Optional[str] = None,
        response_sample: Optional[str] = None,
        banner_output: Optional[str] = None,
        config_snippet: Optional[str] = None,
        stdout_summary: Optional[str] = None,
        *,
        assessment_id: Optional[str] = None,
        asset: Optional[str] = None,
        tool: Optional[str] = None,
        tool_version: Optional[str] = None,
        request_excerpt: Optional[str] = None,
        response_excerpt: Optional[str] = None,
        method: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> EvidenceRecord:
        req_raw = request_excerpt if request_excerpt is not None else request_sample
        resp_raw = response_excerpt if response_excerpt is not None else response_sample

        req_clean, red1 = self.redact_sensitive_data(req_raw)
        resp_clean, red2 = self.redact_sensitive_data(resp_raw)
        banner_clean, red3 = self.redact_sensitive_data(banner_output)
        config_clean, red4 = self.redact_sensitive_data(config_snippet)
        stdout_clean, red5 = self.redact_sensitive_data(stdout_summary)

        all_redacted = list(set(red1 + red2 + red3 + red4 + red5))
        has_redaction = len(all_redacted) > 0

        eff_assessment_id = assessment_id or finding_id or ""
        eff_asset = asset or asset_id or ""
        eff_tool = tool or tool_source or ""
        eff_method = method or technique or ""
        eff_ts = timestamp or datetime.now(timezone.utc)

        evidence = EvidenceRecord(
            assessment_id=eff_assessment_id,
            asset=eff_asset,
            tool=eff_tool,
            tool_version=tool_version or "1.0.0",
            request_excerpt=req_clean[:8000] if req_clean else None,
            response_excerpt=resp_clean[:8000] if resp_clean else None,
            timestamp=eff_ts,
            method=eff_method,
            redaction_flag=has_redaction,
            finding_id=eff_assessment_id,
            asset_id=eff_asset,
            tool_source=eff_tool,
            technique=eff_method,
            request_sample=req_clean[:8000] if req_clean else None,
            response_sample=resp_clean[:8000] if resp_clean else None,
            banner_output=banner_clean[:4000] if banner_clean else None,
            config_snippet=config_clean[:4000] if config_clean else None,
            stdout_summary=stdout_clean[:4000] if stdout_clean else None,
            redacted_fields=all_redacted,
            collected_at=eff_ts,
        )

        h = self.calculate_sha256(evidence.model_dump())
        evidence.hash = h
        evidence.sha256_hash = h
        return evidence

    async def collect_and_store(
        self,
        finding_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        tool_source: Optional[str] = None,
        technique: Optional[str] = None,
        request_sample: Optional[str] = None,
        response_sample: Optional[str] = None,
        banner_output: Optional[str] = None,
        config_snippet: Optional[str] = None,
        stdout_summary: Optional[str] = None,
        *,
        assessment_id: Optional[str] = None,
        asset: Optional[str] = None,
        tool: Optional[str] = None,
        tool_version: Optional[str] = None,
        request_excerpt: Optional[str] = None,
        response_excerpt: Optional[str] = None,
        method: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        db: Any = None,
    ) -> EvidenceRecord:
        """Sanitize, hash, and persist technical evidence asynchronously."""
        evidence = self._prepare_evidence_record(
            finding_id=finding_id,
            asset_id=asset_id,
            tool_source=tool_source,
            technique=technique,
            request_sample=request_sample,
            response_sample=response_sample,
            banner_output=banner_output,
            config_snippet=config_snippet,
            stdout_summary=stdout_summary,
            assessment_id=assessment_id,
            asset=asset,
            tool=tool,
            tool_version=tool_version,
            request_excerpt=request_excerpt,
            response_excerpt=response_excerpt,
            method=method,
            timestamp=timestamp,
        )

        target_db = db or self._get_db()
        await target_db["evidence_records"].insert_one(evidence.model_dump())
        logger.info(f"[EvidenceCollector] Captured evidence {evidence.id} (hash={evidence.hash[:12]}...)")
        return evidence

    def collect_and_store_sync(
        self,
        finding_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        tool_source: Optional[str] = None,
        technique: Optional[str] = None,
        request_sample: Optional[str] = None,
        response_sample: Optional[str] = None,
        banner_output: Optional[str] = None,
        config_snippet: Optional[str] = None,
        stdout_summary: Optional[str] = None,
        *,
        assessment_id: Optional[str] = None,
        asset: Optional[str] = None,
        tool: Optional[str] = None,
        tool_version: Optional[str] = None,
        request_excerpt: Optional[str] = None,
        response_excerpt: Optional[str] = None,
        method: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        db: Any = None,
    ) -> EvidenceRecord:
        """Sanitize, hash, and persist technical evidence synchronously."""
        evidence = self._prepare_evidence_record(
            finding_id=finding_id,
            asset_id=asset_id,
            tool_source=tool_source,
            technique=technique,
            request_sample=request_sample,
            response_sample=response_sample,
            banner_output=banner_output,
            config_snippet=config_snippet,
            stdout_summary=stdout_summary,
            assessment_id=assessment_id,
            asset=asset,
            tool=tool,
            tool_version=tool_version,
            request_excerpt=request_excerpt,
            response_excerpt=response_excerpt,
            method=method,
            timestamp=timestamp,
        )

        target_db = db
        if target_db is None:
            from workers.recon_worker import _get_db_sync
            try:
                target_db = _get_db_sync()
            except Exception:
                target_db = None

        if target_db is not None:
            try:
                target_db["evidence_records"].insert_one(evidence.model_dump())
            except Exception as e:
                logger.warning(f"[EvidenceCollector] Could not persist evidence sync: {e}")

        logger.info(f"[EvidenceCollector] Captured evidence sync {evidence.id} (hash={evidence.hash[:12]}...)")
        return evidence

    async def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        db = self._get_db()
        doc = await db["evidence_records"].find_one({"id": evidence_id}, {"_id": 0})
        if not doc:
            return None
        return EvidenceRecord(**doc)

    def verify_integrity(self, evidence: EvidenceRecord) -> bool:
        """Verify that stored evidence matches its cryptographic SHA-256 hash."""
        expected_hash = self.calculate_sha256(evidence.model_dump())
        return (evidence.hash == expected_hash) or (evidence.sha256_hash == expected_hash)


evidence_collector = EvidenceCollector()
