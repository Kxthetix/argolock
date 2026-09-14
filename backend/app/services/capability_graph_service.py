"""
ARGOLOCK V1.7 Capability Graph & Attack Path Engine
Models attacker capabilities unlocked by vulnerabilities rather than isolated CVEs,
discovering multi-stage attack chains leading to terminal business impact.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional
from app.models.v1_7_models import AttackChain, CapabilityEdge, CapabilityNode, utc_now_iso


# Mapping vulnerability types/titles to Attacker Capabilities
CAPABILITY_RULES = [
    {
        "keywords": ["sql injection", "sqli"],
        "name": "Execute Arbitrary Database Queries",
        "description": "Attacker can read, extract, or tamper with backend database structures via SQL injection.",
        "terminal": False,
        "leads_to": ["Exfiltrate Customer Database Records", "Authentication Bypass"],
    },
    {
        "keywords": ["idor", "insecure direct object", "broken object level authorization"],
        "name": "Unauthorized Horizontal Record Access",
        "description": "Attacker can query or mutate other tenants' private data records without authorization.",
        "terminal": False,
        "leads_to": ["Exfiltrate Sensitive User Profiles", "Modify Tenant Assets"],
    },
    {
        "keywords": ["xss", "cross-site scripting"],
        "name": "Client-Side Session Hijacking & Script Execution",
        "description": "Attacker executes JavaScript in victim browsers, capable of harvesting session cookies and tokens.",
        "terminal": False,
        "leads_to": ["Impersonate Authenticated Administrator"],
    },
    {
        "keywords": ["ssrf", "server-side request forgery"],
        "name": "Internal Network & Cloud Metadata Query",
        "description": "Attacker pivots HTTP requests to internal microservices and AWS/GCP instance metadata endpoints.",
        "terminal": False,
        "leads_to": ["Steal Cloud IAM Credentials"],
    },
    {
        "keywords": ["command injection", "rce", "remote code execution"],
        "name": "Execute Arbitrary Host Commands",
        "description": "Attacker gains full shell-level command execution capability on target server.",
        "terminal": True,
        "leads_to": ["Complete Server Takeover"],
    },
    {
        "keywords": ["auth bypass", "broken authentication", "jwt"],
        "name": "Administrative Authentication Bypass",
        "description": "Attacker bypasses credential verification, gaining unauthenticated admin session access.",
        "terminal": True,
        "leads_to": ["Administrative Takeover"],
    },
    {
        "keywords": ["dmarc", "spf", "email spoofing"],
        "name": "Impersonate Organization Email Domain",
        "description": "Attacker sends spoofed phishing emails appearing as official target domain.",
        "terminal": False,
        "leads_to": ["Targeted Executive Phishing"],
    },
]


class CapabilityGraphService:
    """
    Constructs and queries the Attacker Capability Graph from verified findings.
    """

    @classmethod
    def generate_graph(cls, scan_id: str, findings: List[Dict[str, Any]], target: str = "") -> Dict[str, Any]:
        nodes: List[CapabilityNode] = []
        edges: List[CapabilityEdge] = []
        node_lookup: Dict[str, CapabilityNode] = {}

        # 1. Derive capability nodes from findings
        for f in findings:
            title = (f.get("title") or "").lower()
            desc = (f.get("description") or "").lower()
            endpoint = f.get("affected_endpoint") or target
            f_id = f.get("id")

            matched_rule = None
            for rule in CAPABILITY_RULES:
                if any(kw in title or kw in desc for kw in rule["keywords"]):
                    matched_rule = rule
                    break

            if matched_rule:
                cap_name = matched_rule["name"]
                cap_desc = matched_rule["description"]
                is_terminal = matched_rule["terminal"]
            else:
                cap_name = f"Exploit {f.get('title', 'Weakness')}"
                cap_desc = f"Attacker leverages {f.get('title')} on {endpoint}."
                is_terminal = (f.get("severity") or "").lower() == "critical"

            evidence_str = f"{f_id}::{title}::{endpoint}"
            ev_hash = hashlib.sha256(evidence_str.encode("utf-8")).hexdigest()[:16]

            node = CapabilityNode(
                name=cap_name,
                description=cap_desc,
                target_asset=endpoint,
                finding_id=f_id,
                confidence=round(float(f.get("cvss_score", 5.0)) / 10.0, 2),
                terminal_impact=is_terminal,
                evidence_hash=ev_hash,
            )
            nodes.append(node)
            node_lookup[node.id] = node

        # 2. Derive capability edges & chain transitions
        # Connect capabilities when one naturally enables subsequent progression
        for i in range(len(nodes) - 1):
            source = nodes[i]
            target_node = nodes[i + 1]
            edge = CapabilityEdge(
                source_id=source.id,
                target_id=target_node.id,
                transition_vulnerability=source.name,
                transition_confidence=round(min(source.confidence, target_node.confidence), 2),
                evidence_hash=source.evidence_hash or "",
            )
            edges.append(edge)
            target_node.prerequisite_node_ids.append(source.id)

        # 3. Construct attack chains
        chains: List[AttackChain] = []
        if nodes:
            chain_nodes = nodes[:4] # Build primary verified chain
            has_terminal = any(n.terminal_impact for n in chain_nodes)
            terminal_desc = chain_nodes[-1].name if chain_nodes else "Potential Exposure"

            chains.append(AttackChain(
                scan_id=scan_id,
                title=f"Attack Path: {chain_nodes[0].name} ➔ {terminal_desc}",
                entry_point=chain_nodes[0].target_asset,
                terminal_impact=terminal_desc,
                path_nodes=chain_nodes,
                overall_confidence=round(sum(n.confidence for n in chain_nodes) / len(chain_nodes), 2),
                severity="critical" if has_terminal else "high",
            ))

        return {
            "scan_id": scan_id,
            "target": target,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": [n.model_dump() for n in nodes],
            "edges": [e.model_dump() for e in edges],
            "attack_chains": [c.model_dump() for c in chains],
            "generated_at": utc_now_iso(),
        }
