"""Attack Path Graph Modeling and MITRE ATT&CK Mapping for ARGOLOCK NET v1.6."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.vapt_models import (
    MITREMapping, AttackPathNode, AttackPathEdge, AttackPathGraph
)

# Curated MITRE ATT&CK Knowledgebase for vulnerability categories
MITRE_ATTACK_DB: Dict[str, Dict[str, str]] = {
    "sql injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "sqli": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "xss": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
    },
    "cross-site scripting": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
    },
    "remote code execution": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
    },
    "rce": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
    },
    "privilege escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    "credential": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
    },
    "secrets": {
        "technique_id": "T1552.001",
        "technique_name": "Credentials in Files",
        "tactic": "Credential Access",
    },
    "smb": {
        "technique_id": "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
    },
    "active directory": {
        "technique_id": "T1087.002",
        "technique_name": "Account Discovery: Domain Account",
        "tactic": "Discovery",
    },
    "cors": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
    },
    "header": {
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
    }
}


class AttackPathEngine:
    """Builds risk relationship graphs and maps confirmed vulnerabilities to MITRE ATT&CK tactics."""

    def map_mitre(self, finding: Dict[str, Any]) -> MITREMapping:
        """Map finding to standard MITRE ATT&CK technique."""
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        finding_id = finding.get("id", "")
        asset_id = finding.get("asset_id") or finding.get("affected_endpoint", "unknown")

        matched = None
        for key, entry in MITRE_ATTACK_DB.items():
            if key in title or key in desc:
                matched = entry
                break

        if not matched:
            matched = {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            }

        return MITREMapping(
            technique_id=matched["technique_id"],
            technique_name=matched["technique_name"],
            tactic=matched["tactic"],
            finding_id=finding_id,
            asset_id=asset_id,
            confidence=0.92,
        )

    def generate_attack_path_graph(
        self,
        assessment_id: str,
        target: str,
        findings: List[Dict[str, Any]],
        critical_assets: Optional[List[str]] = None,
    ) -> AttackPathGraph:
        """
        Construct a visual attack path topology without executing lateral movement.
        Internet -> Public Ingress -> Vulnerable Service -> Compromised Asset -> Critical Crown Jewels.
        """
        nodes: List[AttackPathNode] = []
        edges: List[AttackPathEdge] = []

        # Node 1: External Internet
        nodes.append(AttackPathNode(
            node_id="node_internet",
            name="External Adversary",
            node_type="internet",
            metadata={"exposure": "untrusted_public"}
        ))

        # Node 2: Target Entrypoint
        target_node_id = f"node_asset_{target.replace(':', '_').replace('/', '_')}"
        nodes.append(AttackPathNode(
            node_id=target_node_id,
            name=f"Ingress: {target}",
            node_type="asset",
            metadata={"target": target, "internet_facing": True}
        ))

        edges.append(AttackPathEdge(
            source_id="node_internet",
            target_id=target_node_id,
            relationship="targets_public_boundary",
            risk_weight=1.0
        ))

        # Nodes for confirmed vulnerabilities
        critical_vulnerabilities_exist = False
        last_node_id = target_node_id

        for idx, f in enumerate(findings[:5]):
            vuln_id = f"node_vuln_{idx}"
            title = f.get("title", "Security Flaw")
            sev = f.get("severity", "medium").lower()

            if sev in ("critical", "high"):
                critical_vulnerabilities_exist = True

            nodes.append(AttackPathNode(
                node_id=vuln_id,
                name=title,
                node_type="vulnerability",
                metadata={"severity": sev, "cve": f.get("cve_ids", [])}
            ))

            edges.append(AttackPathEdge(
                source_id=last_node_id,
                target_id=vuln_id,
                relationship="exposes_flaw",
                risk_weight=1.5 if sev == "critical" else 1.2
            ))
            last_node_id = vuln_id

        # High-value destination (e.g. Database / Domain Controller)
        destination_name = (critical_assets[0] if critical_assets else "Internal Production Database / DC")
        dest_node_id = "node_critical_crown_jewel"
        nodes.append(AttackPathNode(
            node_id=dest_node_id,
            name=destination_name,
            node_type="critical_data",
            metadata={"tier": "crown_jewel", "business_impact": "critical"}
        ))

        edges.append(AttackPathEdge(
            source_id=last_node_id,
            target_id=dest_node_id,
            relationship="potential_privilege_escalation_pivot",
            risk_weight=1.8 if critical_vulnerabilities_exist else 1.1
        ))

        return AttackPathGraph(
            assessment_id=assessment_id,
            nodes=nodes,
            edges=edges,
            critical_path_identified=critical_vulnerabilities_exist,
            highest_risk_asset=destination_name,
        )


attack_path_engine = AttackPathEngine()
