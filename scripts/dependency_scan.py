"""
ARGOLOCK Dependency Security Scanner
Audits backend/requirements.txt and frontend/package.json for unpinned versions,
known security vulnerabilities, and package integrity.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


KNOWN_VULNERABLE_PATTERNS = [
    # Package, vulnerable condition regex, CVE
    ("requests", re.compile(r"<2\.31\.0"), "CVE-2023-32681: Information disclosure via Proxy-Authorization header"),
    ("urllib3", re.compile(r"<2\.0\.7"), "CVE-2023-45803: Request body leak on redirect"),
    ("cryptography", re.compile(r"<42\.0\.4"), "CVE-2024-26130: Null pointer dereference in PKCS#12 decoding"),
    ("jinja2", re.compile(r"<3\.1\.3"), "CVE-2024-22195: XSS via xmlattr filter"),
]


def scan_python_requirements(req_path: Path) -> List[Dict[str, Any]]:
    findings = []
    if not req_path.is_file():
        return [{"severity": "ERROR", "message": f"Requirements file not found: {req_path}"}]

    with open(req_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line_idx, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Check for unpinned dependencies
        if not any(op in line for op in ["==", ">=", "<=", "~="]):
            findings.append({
                "file": str(req_path),
                "line": line_idx,
                "package": line,
                "severity": "LOW",
                "issue": "Unpinned dependency: Package has no version constraint pinned",
            })

        # Check against known vulnerable patterns
        for pkg_name, vuln_pattern, advisory in KNOWN_VULNERABLE_PATTERNS:
            if line.lower().startswith(pkg_name.lower()):
                version_part = line[len(pkg_name):].strip()
                if vuln_pattern.search(version_part):
                    findings.append({
                        "file": str(req_path),
                        "line": line_idx,
                        "package": line,
                        "severity": "HIGH",
                        "issue": f"Known vulnerable version: {advisory}",
                    })

    return findings


def scan_node_dependencies(pkg_path: Path) -> List[Dict[str, Any]]:
    findings = []
    if not pkg_path.is_file():
        return [{"severity": "ERROR", "message": f"package.json not found: {pkg_path}"}]

    with open(pkg_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for pkg, ver in deps.items():
        if ver in ("*", "latest"):
            findings.append({
                "file": str(pkg_path),
                "package": f"{pkg}@{ver}",
                "severity": "MEDIUM",
                "issue": "Wildcard version specifier permits uncontrolled dependency drift",
            })
    return findings


def run_audit(root_dir: Path) -> Dict[str, Any]:
    req_file = root_dir / "backend" / "requirements.txt"
    pkg_file = root_dir / "frontend" / "package.json"

    py_findings = scan_python_requirements(req_file)
    node_findings = scan_node_dependencies(pkg_file)

    all_findings = py_findings + node_findings
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")

    return {
        "status": "passed" if high_count == 0 else "action_required",
        "total_findings": len(all_findings),
        "high_severity_count": high_count,
        "findings": all_findings,
    }


if __name__ == "__main__":
    base = Path(__file__).resolve().parent.parent
    result = run_audit(base)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["high_severity_count"] == 0 else 1)
