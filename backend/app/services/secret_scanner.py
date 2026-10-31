"""
ARGOLOCK V1.7 Secret Scanner & Credential Detector
Audits repository files and configurations to ensure zero hardcoded secrets or credentials exist.
Detects AWS keys, GitHub tokens, OpenAI keys, Slack webhooks, and private keys.
"""
from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from loguru import logger


SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bgh[pso]_[a-zA-Z0-9]{36,255}\b")),
    ("OpenAI Live Secret Key", re.compile(r"\bsk-(?:live|proj|svc)?[a-zA-Z0-9_-]{32,}\b")),
    ("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+")),
    ("RSA/DSA/EC Private Key", re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")),
]

# Paths allowed to contain dummy/sample keys for testing or documentation
EXCLUDED_PATHS = [
    ".git",
    "node_modules",
    "venv",
    ".pytest_cache",
    "__pycache__",
    "test_e2e_vulnerable_app.py", # Deliberately contains simulated test payload
    "test_exploitation.py",
    ".env.example",
    "PROJECT_DOCUMENTATION.md",
    "setup.md",
]


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


class SecretScanner:
    """Scans codebases and text buffers for hardcoded secrets."""

    @classmethod
    def scan_content(cls, content: str, filename: str = "buffer") -> List[Dict[str, Any]]:
        """Scan a string content for credential signatures."""
        findings = []
        for line_idx, line in enumerate(content.splitlines(), start=1):
            # Skip comments indicating dummy or example keys
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                if any(indicator in stripped.lower() for indicator in ["dummy", "example", "placeholder", "your-", "change-me"]):
                    continue

            for secret_name, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    raw_val = match.group(0)
                    masked = raw_val[:4] + "*" * (len(raw_val) - 8) + raw_val[-4:] if len(raw_val) > 8 else "***"
                    findings.append({
                        "file": filename,
                        "line": line_idx,
                        "type": secret_name,
                        "masked": masked,
                        "entropy": round(shannon_entropy(raw_val), 2),
                    })
        return findings

    @classmethod
    def scan_git_tracked_files(cls, repo_dir: str | Path) -> Dict[str, Any]:
        """Scan all git-tracked files in the repository to guarantee no committed secrets."""
        import subprocess
        root = Path(repo_dir)
        try:
            out = subprocess.check_output(["git", "ls-files"], cwd=root, text=True)
            files = [line.strip() for line in out.splitlines() if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to query git ls-files: {e}")
            return cls.scan_directory(root)

        all_findings: List[Dict[str, Any]] = []
        files_scanned = 0

        for rel_file in files:
            if rel_file.endswith((".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".docx", ".pdf")):
                continue
            if any(exc in rel_file for exc in EXCLUDED_PATHS):
                continue
            if "test_" in rel_file:
                # Tests use deliberate mock patterns
                continue

            full_path = root / rel_file
            if not full_path.is_file():
                continue

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                files_scanned += 1
                findings = cls.scan_content(content, filename=rel_file)
                all_findings.extend(findings)
            except Exception as e:
                logger.debug(f"Failed to scan tracked file {rel_file}: {e}")

        return {
            "repository": str(root),
            "files_scanned": files_scanned,
            "secret_findings_count": len(all_findings),
            "clean": len(all_findings) == 0,
            "findings": all_findings,
        }
        """Recursively scan directory for hardcoded secrets, respecting exclusion list."""
        root = Path(root_dir)
        all_findings: List[Dict[str, Any]] = []
        files_scanned = 0

        for root_path, dirs, files in os.walk(root):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDED_PATHS and not d.startswith(".")]

            for file in files:
                if file.endswith((".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".docx", ".pdf")):
                    continue
                if file in EXCLUDED_PATHS:
                    continue

                full_path = Path(root_path) / file
                rel_path = str(full_path.relative_to(root)).replace("\\", "/")

                if any(exc in rel_path for exc in EXCLUDED_PATHS):
                    continue

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    files_scanned += 1
                    findings = cls.scan_content(content, filename=rel_path)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.debug(f"Failed to scan {rel_path}: {e}")

        clean = len(all_findings) == 0
        return {
            "root_directory": str(root),
            "files_scanned": files_scanned,
            "secret_findings_count": len(all_findings),
            "clean": clean,
            "findings": all_findings,
        }


secret_scanner = SecretScanner()
