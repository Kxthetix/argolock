"""
Agent 5: Shannon Agent
- Calculates Shannon Entropy to find high-entropy random strings representing credentials.
- Combines entropy with regex signatures for high-fidelity secret detection (Private Keys, AWS keys, etc.).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Dict, List

from loguru import logger

from agents.base_agent import BaseAgent
from ai_providers.base_provider import BaseProvider


class ShannonAgent(BaseAgent):
    """AI/Mathematical agent to detect exposed keys and high-entropy secrets."""

    def __init__(self, provider: BaseProvider):
        super().__init__(provider)
        # Regex patterns for specific high-fidelity credential formats
        self.signatures = {
            "private_key": re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
            "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "aws_secret_key": re.compile(r"\b[0-9a-zA-Z/+]{40}\b"), # Usually verified contextually
            "slack_token": re.compile(r"\bxox[bapr]-[0-9a-zA-Z]{10,48}\b"),
            "github_token": re.compile(r"\bgh[opsg]_[0-9a-zA-Z]{36,255}\b"),
            # Generic key=value or key:value assignments
            "generic_assignment": re.compile(
                r"(?i)(api_key|api_secret|app_secret|secret_key|private_key|auth_token|"
                r"jwt_token|password|passwd|db_password|db_pass|db_uri|database_url)"
                r"\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\~\+\/=]{16,120})['\"]"
            )
        }

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate the Shannon Entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        counter = Counter(data)
        length = len(data)
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    async def scan_content(self, content: str, source_label: str) -> List[Dict[str, Any]]:
        """Scan content mathematically and return a list of identified secrets."""
        findings = []

        if not content:
            return findings

        # 1. Check for Private Keys (Highest severity, immediate match)
        if self.signatures["private_key"].search(content):
            findings.append({
                "title": "Exposed Private Key Block",
                "description": f"An exposed cryptographic private key block (PEM format) was detected in {source_label}. Unauthorized access to private keys allows attackers to decrypt traffic or impersonate servers.",
                "severity": "critical",
                "owasp_category": "A02:2021 Cryptographic Failures",
                "affected_endpoint": source_label,
                "tool_source": "shannon-agent",
                "tags": ["cryptography", "private-key", "credentials-leak"],
                "poc": {
                    "request": "GET " + source_label,
                    "response": "[PEM Private Key Block Detected]",
                    "payload": "PEM structure match",
                    "reproduction_steps": [f"Request the path: {source_label}", "Inspect response for PEM header"]
                }
            })

        # 2. Check for AWS Access Keys
        for aws_match in self.signatures["aws_access_key"].finditer(content):
            key = aws_match.group(0)
            findings.append({
                "title": "Exposed AWS Access Key ID",
                "description": f"An AWS Access Key ID ({key}) was found exposed in {source_label}. This key can be used to authenticate API requests to AWS resources.",
                "severity": "high",
                "owasp_category": "A05:2021 Security Misconfiguration",
                "affected_endpoint": source_label,
                "tool_source": "shannon-agent",
                "tags": ["credentials-leak", "aws", "cloud-security"],
                "poc": {
                    "request": "GET " + source_label,
                    "response": f"... {key} ...",
                    "payload": "AWS Key regex match",
                    "reproduction_steps": [f"Audit content at {source_label}", f"Locate signature {key}"]
                }
            })

        # 3. Check for Github Tokens
        for gh_match in self.signatures["github_token"].finditer(content):
            token = gh_match.group(0)
            findings.append({
                "title": "Exposed GitHub Personal Access Token",
                "description": f"A GitHub token was identified in {source_label}. Attackers can use this token to access repository source code, release assets, or organization settings.",
                "severity": "critical",
                "owasp_category": "A07:2021 Identification and Authentication Failures",
                "affected_endpoint": source_label,
                "tool_source": "shannon-agent",
                "tags": ["credentials-leak", "github", "token"],
                "poc": {
                    "request": "GET " + source_label,
                    "response": f"... {token[:8]}... ...",
                    "payload": "GitHub token format prefix match",
                    "reproduction_steps": [f"Inspect {source_label} for GitHub credential prefixes"]
                }
            })

        # 4. Check for Slack Tokens
        for slack_match in self.signatures["slack_token"].finditer(content):
            token = slack_match.group(0)
            findings.append({
                "title": "Exposed Slack Bot or User Token",
                "description": f"A Slack API token ({token[:15]}...) was found in {source_label}. This exposes the Slack workspace to unauthorized messaging or data extraction.",
                "severity": "high",
                "owasp_category": "A07:2021 Identification and Authentication Failures",
                "affected_endpoint": source_label,
                "tool_source": "shannon-agent",
                "tags": ["credentials-leak", "slack", "token"],
                "poc": {
                    "request": "GET " + source_label,
                    "response": f"... {token[:12]}... ...",
                    "payload": "Slack bot/user token prefix match",
                    "reproduction_steps": [f"Audit endpoint {source_label} for Slack token signatures"]
                }
            })

        # 5. Check for generic high-entropy variables
        for var_match in self.signatures["generic_assignment"].finditer(content):
            var_name = var_match.group(1)
            val = var_match.group(2)
            entropy = self.calculate_entropy(val)

            # High entropy threshold for credentials (e.g. >= 3.2 for short secrets, or 3.8+ generally)
            if entropy >= 3.5:
                findings.append({
                    "title": f"Exposed Credentials in Configuration ({var_name})",
                    "description": f"An assignment to a sensitive variable name ({var_name}) with a high-entropy value (entropy: {entropy:.2f}) was found in {source_label}. This indicates an exposed API key or database password.",
                    "severity": "high" if "pass" not in var_name.lower() else "critical",
                    "owasp_category": "A02:2021 Cryptographic Failures",
                    "affected_endpoint": source_label,
                    "affected_parameter": var_name,
                    "tool_source": "shannon-agent",
                    "tags": ["credentials-leak", "configuration", "entropy"],
                    "poc": {
                        "request": "GET " + source_label,
                        "response": f"{var_name} = '{val[:4]}...{val[-4:]}'" if len(val) > 8 else f"{var_name} = '{val}'",
                        "payload": f"Entropy analysis confirms randomness: {entropy:.2f}",
                        "reproduction_steps": [f"Open {source_label}", f"Search for variable {var_name}"]
                    }
                })

        # 6. General raw high-entropy string scan (tokens/secrets not tied to specific variable names)
        # Look for alphanumeric + key symbols of length 20 to 80
        raw_candidates = re.findall(r"\b[a-zA-Z0-9\-\.\_\~\+\/=]{20,80}\b", content)
        for cand in set(raw_candidates):
            # Exclude strings containing common structures that are NOT keys (e.g. CSS class lists, long words, URLs)
            if "/" in cand and ("http:" in cand or "https:" in cand or "www." in cand):
                continue
            # Skip if it is all a single repeated character
            if len(set(cand)) <= 4:
                continue

            entropy = self.calculate_entropy(cand)
            # High threshold for standalone strings to avoid false positives (standard is 4.5+)
            if entropy >= 4.5:
                # Make sure we didn't already flag this value in the generic assignments
                if any(cand in str(f.get("poc", {}).get("response", "")) for f in findings):
                    continue

                findings.append({
                    "title": "High-Entropy Secret Token Detected",
                    "description": f"A standalone high-entropy string of length {len(cand)} (entropy: {entropy:.2f}) was detected in {source_label}. This character distribution strongly matches cryptographic keys, salts, or API tokens.",
                    "severity": "medium",
                    "owasp_category": "A02:2021 Cryptographic Failures",
                    "affected_endpoint": source_label,
                    "tool_source": "shannon-agent",
                    "tags": ["entropy", "token-leak", "cryptography"],
                    "poc": {
                        "request": "GET " + source_label,
                        "response": f"... {cand[:4]}...{cand[-4:]} ...",
                        "payload": f"Entropy score: {entropy:.2f}",
                        "reproduction_steps": [f"Verify content of {source_label}", f"Search for high-entropy pattern: {cand[:4]}..."]
                    }
                })

        return findings
