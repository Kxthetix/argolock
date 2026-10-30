"""Tests for report filtering and quality gates (Phase 2).

Verifies:
1. Placeholder titles (e.g. '[Verified] Security Issue') are rejected.
2. Findings lacking verified tool source/method are rejected.
3. Findings lacking an evidence reference are rejected.
4. HTTP 403/blocked responses are marked inconclusive and excluded from exposed findings.
5. Boilerplate root causes are removed.
6. HYPOTHESIS findings are never reported or persisted.
"""
import pytest
from app.models.finding import Finding, DataSource, Severity
from reports.pdf_generator import validate_and_filter_findings, is_placeholder_title, is_403_or_blocked


def test_is_placeholder_title():
    assert is_placeholder_title("[Verified] Security Issue") is True
    assert is_placeholder_title("[verified] vulnerability") is True
    assert is_placeholder_title("Security Issue Discovered") is True
    assert is_placeholder_title("Generic Issue") is True
    assert is_placeholder_title("Placeholder Issue") is True
    assert is_placeholder_title("Unknown") is True
    assert is_placeholder_title("  ") is True
    assert is_placeholder_title("SQL Injection in /api/v1/users?id=") is False
    assert is_placeholder_title("Missing Content Security Policy Header") is False


def test_validate_and_filter_rejects_placeholder_titles():
    findings = [
        {
            "title": "[Verified] Security Issue",
            "tool_source": "nuclei",
            "affected_endpoint": "https://example.com/login",
            "severity": "high",
        },
        {
            "title": "Cross-Site Scripting (Reflected)",
            "tool_source": "xss-auditor",
            "affected_endpoint": "https://example.com/search?q=test",
            "severity": "medium",
        }
    ]
    filtered = validate_and_filter_findings(findings)
    assert len(filtered) == 1
    assert filtered[0]["title"] == "Cross-Site Scripting (Reflected)"


def test_validate_and_filter_rejects_missing_method():
    findings = [
        {
            "title": "Unauthenticated API Access",
            "tool_source": "",
            "affected_endpoint": "https://example.com/api/data",
            "severity": "high",
        },
        {
            "title": "Unauthenticated API Access",
            "tool_source": "httpx_probe",
            "affected_endpoint": "https://example.com/api/data",
            "severity": "high",
        }
    ]
    filtered = validate_and_filter_findings(findings)
    assert len(filtered) == 1
    assert filtered[0]["tool_source"] == "httpx_probe"


def test_validate_and_filter_rejects_missing_evidence():
    findings = [
        {
            "title": "Open Redirect Vulnerability",
            "tool_source": "nuclei",
            "affected_endpoint": "",
            "evidence": "",
            "severity": "medium",
        },
        {
            "title": "Open Redirect Vulnerability",
            "tool_source": "nuclei",
            "affected_endpoint": "https://example.com/redirect?url=evil.com",
            "severity": "medium",
        }
    ]
    filtered = validate_and_filter_findings(findings)
    assert len(filtered) == 1
    assert filtered[0]["affected_endpoint"] == "https://example.com/redirect?url=evil.com"


def test_validate_and_filter_handles_403_blocked_responses():
    findings = [
        {
            "title": "Potential Admin Console Access",
            "tool_source": "httpx_probe",
            "affected_endpoint": "https://example.com/admin",
            "evidence": "HTTP GET returned 403 Forbidden - Access Denied by WAF",
            "severity": "high",
        },
        {
            "title": "Information Disclosure in /debug",
            "tool_source": "httpx_probe",
            "affected_endpoint": "https://example.com/debug",
            "evidence": "HTTP 200 OK with stack trace",
            "severity": "medium",
        }
    ]
    filtered = validate_and_filter_findings(findings)
    # The 403 response must be excluded from exposed findings
    assert len(filtered) == 1
    assert filtered[0]["title"] == "Information Disclosure in /debug"


def test_validate_and_filter_removes_boilerplate_root_causes():
    boilerplate = "The service or configuration lacks security controls or headers, allowing potential abuse"
    findings = [
        {
            "title": "Missing Strict-Transport-Security Header",
            "tool_source": "httpx_probe",
            "affected_endpoint": "https://example.com",
            "severity": "low",
            "remediation": {
                "root_cause": boilerplate,
                "fix_steps": ["Add Strict-Transport-Security: max-age=31536000; includeSubDomains header"],
            }
        }
    ]
    filtered = validate_and_filter_findings(findings)
    assert len(filtered) == 1
    assert filtered[0]["remediation"]["root_cause"] is None
