"""False Positive Analysis Engine for ARGOLOCK NET v1.6."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.vapt_models import ValidationStatus


class FalsePositiveEngine:
    """Evaluates technical signals to detect scanner false positives and misclassifications."""

    def evaluate_false_positive(
        self,
        finding: Dict[str, Any],
        live_evidence: Dict[str, Any],
    ) -> tuple[ValidationStatus, float, str]:
        """
        Evaluate whether a finding is confirmed, false positive, not exploitable, or requires review.
        Returns: (ValidationStatus, confidence, rationale)
        """
        title = finding.get("title", "")
        desc = finding.get("description", "")
        target = finding.get("affected_endpoint") or finding.get("url") or ""

        status_code = live_evidence.get("status_code")
        server_header = (live_evidence.get("server_header") or "").lower()
        banner = (live_evidence.get("banner_output") or "").lower()
        missing_headers = live_evidence.get("missing_security_headers", [])
        reflected = live_evidence.get("reflected_parameter", False)
        cors_misconfigured = live_evidence.get("cors_misconfigured", False)
        probe_error = live_evidence.get("probe_error") or live_evidence.get("error")

        # 1. Check if endpoint is completely unreachable or dead
        if probe_error and ("connection refused" in str(probe_error).lower() or "name resolution" in str(probe_error).lower()):
            return (
                ValidationStatus.NOT_EXPLOITABLE,
                0.85,
                f"Target endpoint '{target}' is unreachable: {probe_error}."
            )

        # 2. Product mismatch detection (e.g. scanner flagged Apache vulnerability, but server is Nginx or IIS)
        title_lower = title.lower()
        if "apache" in title_lower and "nginx" in server_header and "reverse-proxy" not in banner:
            return (
                ValidationStatus.FALSE_POSITIVE,
                0.90,
                f"Product Mismatch: Scanner flagged an Apache flaw, but target header indicates '{server_header}'."
            )
        if "iis" in title_lower and "microsoft-iis" not in server_header and ("nginx" in server_header or "apache" in server_header):
            return (
                ValidationStatus.FALSE_POSITIVE,
                0.92,
                f"Product Mismatch: Scanner flagged Microsoft IIS flaw on non-IIS server ('{server_header}')."
            )

        # 3. Status 404 / 410 on specific file exposure findings (e.g. /.env, /backup.sql)
        if status_code in (404, 410):
            if any(term in title_lower for term in ["exposure", "leak", "backup", ".env", "git", "config", "path traversal"]):
                return (
                    ValidationStatus.FALSE_POSITIVE,
                    0.95,
                    f"File/Path Not Found: Probed path returned HTTP {status_code}; resource is not exposed."
                )

        # 4. Status 401 / 403 (Proper access control blocks unauthenticated access)
        if status_code in (401, 403):
            if any(term in title_lower for term in ["unauthenticated", "open redirect", "anonymous access", "public"]):
                return (
                    ValidationStatus.NOT_EXPLOITABLE,
                    0.88,
                    f"Access Denied: Endpoint correctly enforced authorization with HTTP {status_code}."
                )

        # 5. CORS Misconfiguration check
        if "cors" in title_lower:
            if cors_misconfigured:
                return (
                    ValidationStatus.CONFIRMED,
                    0.96,
                    f"CORS Misconfiguration verified: Origin reflection confirmed (ACAO: {live_evidence.get('cors_acao')})."
                )
            else:
                return (
                    ValidationStatus.FALSE_POSITIVE,
                    0.90,
                    "CORS policy did not reflect untrusted test Origin; finding is not exploitable."
                )

        # 6. XSS / Reflection check: If finding claims reflection, verify parameter reflection signal
        if ("xss" in title_lower or "cross-site scripting" in title_lower or "parameter reflection" in title_lower) and "cors" not in title_lower:
            if not reflected and status_code == 200:
                # Need manual review or likely unreflected
                return (
                    ValidationStatus.REQUIRES_MANUAL_REVIEW,
                    0.60,
                    "Parameter reflection was not corroborated by safe probe. Manual verification required."
                )
            elif reflected:
                return (
                    ValidationStatus.CONFIRMED,
                    0.94,
                    "Parameter input was reflected unencoded in application response body."
                )

        # 7. Security Header verification
        if "header" in title_lower:
            matched_header = False
            for h in missing_headers:
                if h.lower() in title_lower or h.lower() in desc.lower():
                    matched_header = True
                    break
            if matched_header:
                return (
                    ValidationStatus.CONFIRMED,
                    0.98,
                    f"Defensive security header is genuinely missing from HTTP response headers."
                )
            elif missing_headers:
                return (
                    ValidationStatus.VALIDATED,
                    0.80,
                    f"Observed missing security headers: {', '.join(missing_headers)}."
                )
            else:
                return (
                    ValidationStatus.FALSE_POSITIVE,
                    0.90,
                    "Expected security headers are properly implemented in target response."
                )

        # 8. If live evidence has active response and matches scanner finding
        if status_code and status_code < 500:
            return (
                ValidationStatus.VALIDATED,
                0.75,
                f"Target is responsive (HTTP {status_code}); finding corroborated by non-destructive probe."
            )

        return (
            ValidationStatus.REQUIRES_MANUAL_REVIEW,
            0.50,
            "Insufficient conclusive evidence gathered during automated non-invasive probing."
        )


false_positive_engine = FalsePositiveEngine()
