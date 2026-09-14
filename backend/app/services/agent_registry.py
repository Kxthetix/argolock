"""
ARGOLOCK V1.7 60-Agent Logical Registry
Implements the hierarchical agent taxonomy across 9 operational groups.
Agents are defined as lightweight logical profiles dispatched through common workers.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentDefinition(BaseModel):
    id: str                       # e.g., "01"
    code: str                     # e.g., "mission-controller"
    name: str                     # e.g., "Mission Controller"
    category: str                 # Orchestration, Recon, Web/API, Infrastructure, Code, Exploitation, Validation, Risk, Reporting
    description: str
    tools: List[str] = Field(default_factory=list)
    status: str = "active"        # active, idle, running, standby
    capabilities: List[str] = Field(default_factory=list)
    confidence_weight: float = 1.0


class AgentRegistry:
    """
    Catalog and manager for the 60 logical specialist agents.
    """

    _REGISTRY: List[AgentDefinition] = [
        # ── 1. ORCHESTRATION (01-04) ───────────────────────────────────────────
        AgentDefinition(
            id="01", code="mission-controller", name="Mission Controller",
            category="Orchestration",
            description="Coordinates VAPT missions, enforces budgets, dispatches agents, tracks progress, and halts unsafe actions.",
            tools=["gateway", "policy-engine", "budget-tracker"],
            capabilities=["mission_planning", "agent_dispatch", "safety_interlock"]
        ),
        AgentDefinition(
            id="02", code="attack-surface-ranker", name="Attack Surface Ranker",
            category="Orchestration",
            description="Ranks target assets by exposure, business criticality, auth boundary, and technology risk.",
            tools=["risk-scoring", "asset-correlator"],
            capabilities=["surface_ranking", "criticality_scoring"]
        ),
        AgentDefinition(
            id="03", code="correlator", name="Correlator Agent",
            category="Orchestration",
            description="Correlates assets, technologies, CVEs, endpoints, and credentials across the attack lifecycle.",
            tools=["knowledge-base", "mitre-mapper"],
            capabilities=["entity_correlation", "cve_mapping"]
        ),
        AgentDefinition(
            id="04", code="coverage-auditor", name="Coverage Auditor",
            category="Orchestration",
            description="Ensures exhaustive test coverage across target endpoints, parameters, and protocol ports.",
            tools=["diff-engine"],
            capabilities=["coverage_audit", "blindspot_detection"]
        ),

        # ── 2. RECONNAISSANCE (05-11) ──────────────────────────────────────────
        AgentDefinition(
            id="05", code="asset-discovery", name="Asset Discovery Agent",
            category="Recon",
            description="Performs passive & active subdomain enumeration, certificate transparency searches, and IP resolution.",
            tools=["subfinder", "amass", "assetfinder"],
            capabilities=["subdomain_enum", "ct_search", "ip_discovery"]
        ),
        AgentDefinition(
            id="06", code="dns", name="DNS Specialist Agent",
            category="Recon",
            description="Discovers A/AAAA, CNAME, MX, TXT, NS records, wildcard resolution, and dangling takeover records.",
            tools=["dnsx", "massdns", "dig"],
            capabilities=["dns_records", "takeover_detection", "zone_transfer"]
        ),
        AgentDefinition(
            id="07", code="network-discovery", name="Network Discovery Agent",
            category="Recon",
            description="Performs port scanning, service enumeration, and banner grabbing.",
            tools=["naabu", "nmap", "rustscan"],
            capabilities=["port_scan", "service_detection", "os_fingerprinting"]
        ),
        AgentDefinition(
            id="08", code="web-surface", name="Web Surface Agent",
            category="Recon",
            description="Crawls endpoints, links, forms, parameters, redirects, and HTTP methods.",
            tools=["httpx", "katana", "gau"],
            capabilities=["web_crawling", "parameter_mining", "endpoint_discovery"]
        ),
        AgentDefinition(
            id="09", code="api-discovery", name="API Discovery Agent",
            category="Recon",
            description="Detects REST, OpenAPI/Swagger, GraphQL endpoints, and parameter schemas.",
            tools=["custom-crawler", "graphql-tools"],
            capabilities=["api_introspection", "swagger_parsing", "graphql_schema"]
        ),
        AgentDefinition(
            id="10", code="cloud-recon", name="Cloud Recon Agent",
            category="Recon",
            description="Identifies public S3/Blob storage, serverless functions, and cloud metadata exposure.",
            tools=["cloud-sdk", "trivy"],
            capabilities=["storage_exposure", "cloud_metadata", "iam_boundary"]
        ),
        AgentDefinition(
            id="11", code="technology-fingerprint", name="Technology Fingerprint Agent",
            category="Recon",
            description="Identifies CMS, frameworks, web servers, CDNs, and component versions.",
            tools=["whatweb", "wappalyzer"],
            capabilities=["tech_fingerprint", "version_detection"]
        ),

        # ── 3. WEB/API SPECIALISTS (12-30) ─────────────────────────────────────
        AgentDefinition(
            id="12", code="auth", name="Authentication Specialist",
            category="Web/API",
            description="Validates session management, password policies, MFA bypass, and brute force defenses.",
            tools=["nuclei", "zap"],
            capabilities=["session_hijack", "mfa_bypass", "credential_stuffing"]
        ),
        AgentDefinition(
            id="13", code="idor", name="IDOR Specialist",
            category="Web/API",
            description="Tests for Insecure Direct Object References and multi-tenant authorization bypass.",
            tools=["zap", "custom-replayer"],
            capabilities=["idor_check", "tenant_isolation_test"]
        ),
        AgentDefinition(
            id="14", code="xss", name="XSS Specialist",
            category="Web/API",
            description="Detects Stored, Reflected, and DOM-based Cross-Site Scripting vulnerabilities.",
            tools=["dalfox", "nuclei"],
            capabilities=["xss_detection", "context_aware_polyglot"]
        ),
        AgentDefinition(
            id="15", code="sqli", name="SQL Injection Specialist",
            category="Web/API",
            description="Validates Error, Boolean, and Time-based SQL Injection with safe non-destructive proofs.",
            tools=["sqlmap", "nuclei"],
            capabilities=["sqli_validation", "syntax_probe"]
        ),
        AgentDefinition(
            id="16", code="nosqli", name="NoSQL Injection Specialist",
            category="Web/API",
            description="Tests MongoDB/CouchDB operator injections ($gt, $ne, $regex).",
            tools=["nuclei"],
            capabilities=["nosql_operator_probe"]
        ),
        AgentDefinition(
            id="17", code="ssrf", name="SSRF Specialist",
            category="Web/API",
            description="Tests Server-Side Request Forgery against cloud metadata and internal subnets.",
            tools=["nuclei", "interactsh"],
            capabilities=["ssrf_oob_check", "cloud_metadata_probe"]
        ),
        AgentDefinition(
            id="18", code="ssti", name="SSTI Specialist",
            category="Web/API",
            description="Identifies Server-Side Template Injection across Jinja2, Twig, Freemarker, Velocity.",
            tools=["nuclei"],
            capabilities=["template_injection_math_probe"]
        ),
        AgentDefinition(
            id="19", code="xxe", name="XXE Specialist",
            category="Web/API",
            description="Validates XML External Entity vulnerabilities and schema parsing flaws.",
            tools=["nuclei"],
            capabilities=["xxe_file_disclosure", "xml_entity_test"]
        ),
        AgentDefinition(
            id="20", code="csrf", name="CSRF Specialist",
            category="Web/API",
            description="Checks SameSite cookie flags, anti-CSRF token validation, and state-changing endpoints.",
            tools=["zap"],
            capabilities=["csrf_token_bypass", "samesite_audit"]
        ),
        AgentDefinition(
            id="21", code="cors", name="CORS Specialist",
            category="Web/API",
            description="Audits Access-Control-Allow-Origin, null origin acceptance, and wildcard credentials.",
            tools=["nuclei"],
            capabilities=["cors_misconfiguration_check"]
        ),
        AgentDefinition(
            id="22", code="oauth", name="OAuth Specialist",
            category="Web/API",
            description="Validates redirect_uri validation, state parameter CSRF, and token leakage in OAuth/OIDC.",
            tools=["custom-client"],
            capabilities=["oauth_redirect_leak", "token_validation"]
        ),
        AgentDefinition(
            id="23", code="graphql", name="GraphQL Specialist",
            category="Web/API",
            description="Tests introspection disclosure, circular query DoS, and nested batching flaws.",
            tools=["graphql-tools"],
            capabilities=["graphql_introspection", "depth_limit_audit"]
        ),
        AgentDefinition(
            id="24", code="file-upload", name="File Upload Specialist",
            category="Web/API",
            description="Tests extension validation, MIME bypass, SVG XSS, and path traversal in upload handlers.",
            tools=["custom-client"],
            capabilities=["mime_bypass", "executable_upload_test"]
        ),
        AgentDefinition(
            id="25", code="path-traversal", name="Path Traversal Specialist",
            category="Web/API",
            description="Tests directory traversal and Local File Inclusion (LFI) sequences.",
            tools=["nuclei"],
            capabilities=["dot_dot_slash_probe", "null_byte_test"]
        ),
        AgentDefinition(
            id="26", code="command-injection", name="Command Injection Specialist",
            category="Web/API",
            description="Detects OS command injection via pipes, backticks, and shell separators.",
            tools=["commix", "nuclei"],
            capabilities=["command_sep_probe", "time_delay_verification"]
        ),
        AgentDefinition(
            id="27", code="deserialization", name="Deserialization Specialist",
            category="Web/API",
            description="Checks Java, Python pickle, PHP, and YAML insecure object deserialization.",
            tools=["nuclei"],
            capabilities=["insecure_deserialization_probe"]
        ),
        AgentDefinition(
            id="28", code="open-redirect", name="Open Redirect Specialist",
            category="Web/API",
            description="Audits unvalidated parameter-based redirects and protocol smuggling.",
            tools=["nuclei"],
            capabilities=["unvalidated_redirect_check"]
        ),
        AgentDefinition(
            id="29", code="business-logic", name="Business Logic Specialist",
            category="Web/API",
            description="Tests negative currency amounts, coupon reuse, workflow step skipping, and limit bypass.",
            tools=["custom-replayer"],
            capabilities=["logic_workflow_bypass", "limit_tampering"]
        ),
        AgentDefinition(
            id="30", code="race-condition", name="Race Condition Specialist",
            category="Web/API",
            description="Performs concurrent HTTP request synchronization (Limit-overrun / TOCTOU).",
            tools=["custom-concurrency"],
            capabilities=["race_overrun_test"]
        ),

        # ── 4. INFRASTRUCTURE SPECIALISTS (31-36) ──────────────────────────────
        AgentDefinition(
            id="31", code="tls", name="TLS/SSL Specialist",
            category="Infrastructure",
            description="Audits cipher suites, weak protocol versions (SSLv3, TLS 1.0), and certificate expiry.",
            tools=["nmap", "sslscan"],
            capabilities=["tls_version_audit", "weak_cipher_detection"]
        ),
        AgentDefinition(
            id="32", code="service-misconfiguration", name="Service Misconfiguration Specialist",
            category="Infrastructure",
            description="Checks default banners, debug endpoints, server status pages, and exposed stack traces.",
            tools=["nikto", "httpx"],
            capabilities=["debug_endpoint_audit", "banner_disclosure"]
        ),
        AgentDefinition(
            id="33", code="exposed-service", name="Exposed Service Specialist",
            category="Infrastructure",
            description="Identifies exposed databases (Redis, Mongo, Elasticsearch, Memcached) without auth.",
            tools=["nmap"],
            capabilities=["unauth_db_detection", "internal_port_exposure"]
        ),
        AgentDefinition(
            id="34", code="container", name="Container Security Specialist",
            category="Infrastructure",
            description="Checks exposed Docker daemon sockets, unconfined capabilities, and container breakout vectors.",
            tools=["trivy"],
            capabilities=["docker_socket_audit", "container_breakout_check"]
        ),
        AgentDefinition(
            id="35", code="kubernetes", name="Kubernetes Specialist",
            category="Infrastructure",
            description="Audits exposed kubelet ports, API server anonymous access, and etcd exposure.",
            tools=["kube-bench"],
            capabilities=["k8s_api_audit", "kubelet_check"]
        ),
        AgentDefinition(
            id="36", code="cloud-misconfiguration", name="Cloud Misconfiguration Specialist",
            category="Infrastructure",
            description="Detects public cloud buckets, overly permissive IAM roles, and exposed metadata endpoints.",
            tools=["prowler", "trivy"],
            capabilities=["cloud_bucket_policy", "iam_overgrant_check"]
        ),

        # ── 5. CODE / SAST (37-43) ─────────────────────────────────────────────
        AgentDefinition(
            id="37", code="repo-mapper", name="Repo Architecture Mapper",
            category="Code",
            description="Maps codebase dependencies, frameworks, entrypoints, and architectural layers.",
            tools=["semgrep"],
            capabilities=["architecture_mapping", "language_detection"]
        ),
        AgentDefinition(
            id="38", code="entrypoint", name="Entrypoint Analyzer",
            category="Code",
            description="Discovers web routers, controllers, and RPC entrypoints in source code.",
            tools=["semgrep"],
            capabilities=["route_extraction", "controller_discovery"]
        ),
        AgentDefinition(
            id="39", code="source-sink", name="Source-Sink Analyzer",
            category="Code",
            description="Traces untrusted user input sources to sensitive sinks (eval, query, exec).",
            tools=["semgrep", "codeql"],
            capabilities=["source_sink_tracking"]
        ),
        AgentDefinition(
            id="40", code="data-flow", name="Data Flow Analyzer",
            category="Code",
            description="Validates sanitization, encoding, and validation along data flows.",
            tools=["codeql"],
            capabilities=["taint_analysis"]
        ),
        AgentDefinition(
            id="41", code="secrets", name="Secret Detection Agent",
            category="Code",
            description="Scans for hardcoded API keys, passwords, JWT secrets, and private keys.",
            tools=["gitleaks", "trivy"],
            capabilities=["secret_detection", "entropy_analysis"]
        ),
        AgentDefinition(
            id="42", code="dependency", name="Dependency Vulnerability Agent",
            category="Code",
            description="Audits vulnerable third-party dependencies, CVEs, and outdated libraries.",
            tools=["trivy"],
            capabilities=["sca_audit", "cve_lookup"]
        ),
        AgentDefinition(
            id="43", code="exploitability", name="SAST-to-DAST Exploitability Agent",
            category="Code",
            description="Validates whether a static analysis warning is actually reachable and exploitable via DAST.",
            tools=["semgrep", "httpx"],
            capabilities=["sast_dast_correlation"]
        ),

        # ── 6. EXPLOITATION CONTROLLER (44-49) ──────────────────────────────────
        AgentDefinition(
            id="44", code="exploit-planner", name="Exploit Planner",
            category="Exploitation",
            description="Devises minimal, safe proof-of-concept verification strategies.",
            tools=["planner"],
            capabilities=["poc_planning", "safety_constraint_check"]
        ),
        AgentDefinition(
            id="45", code="poc-builder", name="PoC Builder",
            category="Exploitation",
            description="Constructs non-destructive, single-step reproduction payloads.",
            tools=["custom-client"],
            capabilities=["poc_generation"]
        ),
        AgentDefinition(
            id="46", code="browser-verifier", name="Browser Verifier",
            category="Exploitation",
            description="Executes headless browser sessions to verify DOM-based and client-side impacts.",
            tools=["playwright"],
            capabilities=["dom_xss_verification", "screenshot_capture"]
        ),
        AgentDefinition(
            id="47", code="state-verifier", name="State Verifier",
            category="Exploitation",
            description="Confirms that application state altered by proof is safely restored.",
            tools=["state-checker"],
            capabilities=["state_cleanup", "idempotency_verification"]
        ),
        AgentDefinition(
            id="48", code="capability-extractor", name="Capability Extractor",
            category="Exploitation",
            description="Extracts the concrete attacker capability unlocked by a verified vulnerability.",
            tools=["capability-engine"],
            capabilities=["capability_derivation"]
        ),
        AgentDefinition(
            id="49", code="chain-builder", name="Attack Chain Builder",
            category="Exploitation",
            description="Links compatible attacker capabilities into multi-step attack graphs.",
            tools=["graph-builder"],
            capabilities=["attack_chaining", "path_analysis"]
        ),

        # ── 7. ADVERSARIAL VALIDATION (50-53) ───────────────────────────────────
        AgentDefinition(
            id="50", code="devil-advocate", name="Devil's Advocate Agent",
            category="Validation",
            description="Challenges every candidate finding to attempt to disprove or downgrade false positives.",
            tools=["validator"],
            capabilities=["adversarial_disproof", "false_positive_elimination"]
        ),
        AgentDefinition(
            id="51", code="severity-validator", name="Severity Validator",
            category="Validation",
            description="Calibrates CVSS scores based on practical exploitability and local context.",
            tools=["cvss-calculator"],
            capabilities=["severity_calibration"]
        ),
        AgentDefinition(
            id="52", code="duplicate-validator", name="Duplicate Validator",
            category="Validation",
            description="Eliminates redundant alerts from overlapping scanners.",
            tools=["dedup-engine"],
            capabilities=["deduplication"]
        ),
        AgentDefinition(
            id="53", code="evidence-validator", name="Evidence Validator",
            category="Validation",
            description="Verifies cryptographic hashes and completeness of HTTP request/response proofs.",
            tools=["hash-verifier"],
            capabilities=["evidence_integrity_check"]
        ),

        # ── 8. CYBER RISK & INVESTMENT (54-57) ──────────────────────────────────
        AgentDefinition(
            id="54", code="risk-analyst", name="Cyber Risk Analyst",
            category="Risk",
            description="Calculates multi-variable cyber risk integrating asset value, exposure, and impact.",
            tools=["risk-engine"],
            capabilities=["cyber_risk_quantification"]
        ),
        AgentDefinition(
            id="55", code="attack-technique-mapper", name="ATT&CK Technique Mapper",
            category="Risk",
            description="Maps verified attack chains to MITRE ATT&CK enterprise techniques.",
            tools=["mitre-mapper"],
            capabilities=["mitre_mapping"]
        ),
        AgentDefinition(
            id="56", code="remediation-prioritizer", name="Remediation Prioritizer",
            category="Risk",
            description="Ranks vulnerabilities by net risk reduction rather than raw CVSS severity.",
            tools=["priority-engine"],
            capabilities=["risk_reduction_ranking"]
        ),
        AgentDefinition(
            id="57", code="investment-optimizer", name="Investment Optimizer",
            category="Risk",
            description="Calculates remediation ROI (Risk Reduction vs Implementation Cost) for budget planning.",
            tools=["roi-engine"],
            capabilities=["remediation_roi", "budget_optimization"]
        ),

        # ── 9. REPORTING (58-60) ───────────────────────────────────────────────
        AgentDefinition(
            id="58", code="report-writer", name="Technical Report Writer",
            category="Reporting",
            description="Generates developer-ready, reproducible vulnerability documentation with PoCs.",
            tools=["report-engine"],
            capabilities=["technical_reporting"]
        ),
        AgentDefinition(
            id="59", code="executive-summary", name="Executive Summary Agent",
            category="Reporting",
            description="Produces high-level risk narratives, posture indices, and trend summaries for C-suite.",
            tools=["llm-narrative"],
            capabilities=["executive_narrative"]
        ),
        AgentDefinition(
            id="60", code="compliance-mapper", name="Compliance Mapper",
            category="Reporting",
            description="Maps findings and remediation outcomes to ISO 27001, SOC 2, PCI-DSS, and HIPAA controls.",
            tools=["compliance-engine"],
            capabilities=["compliance_crosswalk"]
        ),
    ]

    @classmethod
    def list_agents(cls, category: Optional[str] = None) -> List[AgentDefinition]:
        if category:
            return [a for a in cls._REGISTRY if a.category.lower() == category.lower()]
        return cls._REGISTRY

    @classmethod
    def get_agent(cls, code_or_id: str) -> Optional[AgentDefinition]:
        for a in cls._REGISTRY:
            if a.code == code_or_id or a.id == code_or_id:
                return a
        return None

    @classmethod
    def get_categories(cls) -> List[str]:
        seen = []
        for a in cls._REGISTRY:
            if a.category not in seen:
                seen.append(a.category)
        return seen

    @classmethod
    def total_count(cls) -> int:
        return len(cls._REGISTRY)
