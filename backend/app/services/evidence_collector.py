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
                "finding_id": record_dict.get("finding_id"),
                "asset_id": record_dict.get("asset_id"),
                "tool_source": record_dict.get("tool_source"),
                "technique": record_dict.get("technique"),
                "request_sample": record_dict.get("request_sample"),
                "response_sample": record_dict.get("response_sample"),
                "banner_output": record_dict.get("banner_output"),
                "config_snippet": record_dict.get("config_snippet"),
            },
            sort_keys=True,
            default=str
        )
        return hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()

    async def collect_and_store(
        self,
        finding_id: str,
        asset_id: str,
        tool_source: str,
        technique: str,
        request_sample: Optional[str] = None,
        response_sample: Optional[str] = None,
        banner_output: Optional[str] = None,
        config_snippet: Optional[str] = None,
        stdout_summary: Optional[str] = None,
    ) -> EvidenceRecord:
        """Sanitize, hash, and persist technical evidence."""
        req_clean, red1 = self.redact_sensitive_data(request_sample)
        resp_clean, red2 = self.redact_sensitive_data(response_sample)
        banner_clean, red3 = self.redact_sensitive_data(banner_output)
        config_clean, red4 = self.redact_sensitive_data(config_snippet)
        stdout_clean, red5 = self.redact_sensitive_data(stdout_summary)

        all_redacted = list(set(red1 + red2 + red3 + red4 + red5))

        evidence = EvidenceRecord(
            finding_id=finding_id,
            asset_id=asset_id,
            tool_source=tool_source,
            technique=technique,
            request_sample=req_clean[:8000] if req_clean else None,
            response_sample=resp_clean[:8000] if resp_clean else None,
            banner_output=banner_clean[:4000] if banner_clean else None,
            config_snippet=config_clean[:4000] if config_clean else None,
            stdout_summary=stdout_clean[:4000] if stdout_clean else None,
            redacted_fields=all_redacted,
        )

        evidence.sha256_hash = self.calculate_sha256(evidence.model_dump())

        db = self._get_db()
        await db["evidence_records"].insert_one(evidence.model_dump())
        logger.info(f"[EvidenceCollector] Captured evidence {evidence.id} (SHA256={evidence.sha256_hash[:12]}...)")
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
        return evidence.sha256_hash == expected_hash


evidence_collector = EvidenceCollector()
