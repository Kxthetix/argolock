import agentsJson from './agents_data.json';
import {
  Mission,
  AgentProfile,
  CapabilityGraph,
  CyberRiskQuantification,
  InvestmentPlan,
  ControlPlaneStatus,
  SystemAgentsResponse,
  SystemToolsResponse,
  RemediationAction,
} from './api';

// ── 60 Specialist Agents ─────────────────────────────────────────────────────

export function getDefaultAgents(): { total_agents: number; categories: string[]; agents: AgentProfile[] } {
  return agentsJson as { total_agents: number; categories: string[]; agents: AgentProfile[] };
}

// ── V1.7 Missions ────────────────────────────────────────────────────────────

const LOCAL_MISSIONS_KEY = 'argolock_v17_missions';

export function getLocalMissions(): Mission[] {
  try {
    const raw = localStorage.getItem(LOCAL_MISSIONS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch (_) {}

  const defaultMissions: Mission[] = [
    {
      id: 'mission-primary-nptel',
      name: 'Assessment Mission: https://onlinecourses.nptel.ac.in',
      target: 'https://onlinecourses.nptel.ac.in',
      mode: 'ASSESSMENT',
      status: 'running',
      current_phase: 'Exploitation Validation',
      progress_percent: 68,
      budget_seconds: 600,
      scope_whitelist: ['https://onlinecourses.nptel.ac.in', '*.nptel.ac.in'],
      scope_blacklist: [],
      active_agent_count: 7,
      findings_count: 39,
      verified_count: 8,
      capabilities_count: 6,
      risk_score: 68.5,
      created_at: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 'mission-nmap-discovery',
      name: 'Discovery Mission: http://scanme.nmap.org',
      target: 'http://scanme.nmap.org',
      mode: 'DISCOVERY',
      status: 'completed',
      current_phase: 'Reconnaissance',
      progress_percent: 100,
      budget_seconds: 300,
      scope_whitelist: ['http://scanme.nmap.org'],
      scope_blacklist: [],
      active_agent_count: 0,
      findings_count: 5,
      verified_count: 2,
      capabilities_count: 2,
      risk_score: 34.0,
      created_at: new Date(Date.now() - 86400000).toISOString(),
      completed_at: new Date(Date.now() - 86100000).toISOString(),
    },
  ];

  try {
    localStorage.setItem(LOCAL_MISSIONS_KEY, JSON.stringify(defaultMissions));
  } catch (_) {}

  return defaultMissions;
}

export function saveLocalMission(mission: Mission): Mission {
  const list = getLocalMissions();
  const updated = [mission, ...list.filter(m => m.id !== mission.id)];
  try {
    localStorage.setItem(LOCAL_MISSIONS_KEY, JSON.stringify(updated));
  } catch (_) {}
  return mission;
}

// ── Capability Graph ─────────────────────────────────────────────────────────

export function getDefaultCapabilityGraph(scanId: string, target = 'https://onlinecourses.nptel.ac.in'): CapabilityGraph {
  const nodes = [
    {
      id: 'cap-01',
      name: 'External HTTP Service Surface Mapped',
      description: 'Discovery agents mapped active HTTP/HTTPS ports and endpoints on the target domain.',
      target_asset: target,
      confidence: 0.99,
      terminal_impact: false,
      evidence_hash: 'sha256:7a419ef9c42b89d6e',
      discovered_at: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 'cap-02',
      name: 'Client-Side Session Hijacking & Script Execution',
      description: 'Cross-Site Scripting (XSS) / Clickjacking vectors allow script injection in authenticated user context.',
      target_asset: `${target}/e-learning`,
      confidence: 0.88,
      terminal_impact: false,
      evidence_hash: 'sha256:12ef88c03e89ad71f',
      discovered_at: new Date(Date.now() - 2400000).toISOString(),
    },
    {
      id: 'cap-03',
      name: 'Impersonate Organization Email Domain',
      description: 'Missing SPF and DMARC enforcement allows threat actors to forge spoofed communications.',
      target_asset: target,
      confidence: 0.95,
      terminal_impact: false,
      evidence_hash: 'sha256:bb602c3821a7331fa',
      discovered_at: new Date(Date.now() - 1800000).toISOString(),
    },
    {
      id: 'cap-04',
      name: 'Exfiltrate Session Tokens & Elevate Privileges',
      description: 'Hijacked operator sessions leveraged across administrative dashboard API endpoints.',
      target_asset: `${target}/api/admin`,
      confidence: 0.82,
      terminal_impact: true,
      evidence_hash: 'sha256:88fa2901cebb0011c',
      discovered_at: new Date(Date.now() - 900000).toISOString(),
    },
  ];

  const edges = [
    {
      source_id: 'cap-01',
      target_id: 'cap-02',
      transition_vulnerability: 'Missing Security Headers & Clickjacking',
      transition_confidence: 0.92,
      evidence_hash: 'sha256:e0192a88bf00',
    },
    {
      source_id: 'cap-02',
      target_id: 'cap-04',
      transition_vulnerability: 'Session Token Exfiltration & Cookie Theft',
      transition_confidence: 0.84,
      evidence_hash: 'sha256:f0293c77ab11',
    },
  ];

  const attack_chains = [
    {
      id: 'chain-01',
      scan_id: scanId,
      title: 'Target Phishing to Administrative Account Takeover',
      entry_point: 'Domain Email Spoofing & Header Misconfiguration',
      terminal_impact: 'Administrative Session Takeover',
      path_nodes: nodes,
      overall_confidence: 0.86,
      severity: 'high',
      created_at: new Date().toISOString(),
    },
  ];

  return {
    scan_id: scanId,
    target,
    total_nodes: nodes.length,
    total_edges: edges.length,
    nodes,
    edges,
    attack_chains,
    generated_at: new Date().toISOString(),
  };
}

// ── Cyber Risk Quantification ────────────────────────────────────────────────

export function getDefaultCyberRisk(scanId: string): CyberRiskQuantification {
  return {
    scan_id: scanId,
    score: 68.5,
    rating: 'HIGH',
    severity_factor: 7.4,
    exploitability_factor: 6.8,
    asset_criticality_factor: 1.2,
    exposure_factor: 1.3,
    business_impact_factor: 7.2,
    threat_relevance_factor: 1.15,
    confidence_factor: 0.92,
    calculation_breakdown: {
      formula: 'Risk = BaseSeverity x Exploitability x Criticality x Exposure x ThreatRelevance',
      base_severity: 7.4,
      exploitability: 6.8,
      asset_criticality: 1.2,
      exposure: 1.3,
      threat_relevance: 1.15,
      confidence_discount: 0.92,
      raw_score: 68.5,
      max_score: 100.0,
    },
    calculated_at: new Date().toISOString(),
  };
}

// ── Remediation ROI & Investment Plan ─────────────────────────────────────────

export function getDefaultInvestmentPlan(scanId: string): InvestmentPlan {
  const actions: RemediationAction[] = [
    {
      id: 'rem-01',
      title: 'Deploy Strict Content-Security-Policy and X-Frame-Options',
      recommended_control: 'Configure Web Gateway to inject Content-Security-Policy and SAMEORIGIN X-Frame-Options headers.',
      estimated_cost: '$500 - $1,500',
      cost_index: 1,
      risk_reduction_points: 24.5,
      residual_risk_points: 44.0,
      roi_score: 24.5,
      priority: 'P1',
      effort_hours: 4,
      compliance_mappings: ['OWASP-A05', 'CIS-Control-4.3', 'PCI-DSS-6.5.1'],
    },
    {
      id: 'rem-02',
      title: 'Publish Authoritative SPF, DKIM & DMARC Enforcement Records',
      recommended_control: 'Publish TXT record: v=spf1 -all and configure strict DMARC reject policy.',
      estimated_cost: '$200 - $800',
      cost_index: 1,
      risk_reduction_points: 16.0,
      residual_risk_points: 28.0,
      roi_score: 16.0,
      priority: 'P2',
      effort_hours: 2,
      compliance_mappings: ['RFC-7208', 'RFC-7489', 'NIST-800-53-SC-8'],
    },
    {
      id: 'rem-03',
      title: 'Enforce HttpOnly, Secure, and SameSite Flags on Authentication Cookies',
      recommended_control: 'Set SameSite=Lax and HttpOnly on session cookies to mitigate client script theft.',
      estimated_cost: '$1,000 - $3,000',
      cost_index: 2,
      risk_reduction_points: 7.5,
      residual_risk_points: 20.5,
      roi_score: 3.75,
      priority: 'P3',
      effort_hours: 8,
      compliance_mappings: ['OWASP-A07', 'NIST-SP-800-63B'],
    },
  ];

  return {
    scan_id: scanId,
    initial_risk_score: 68.5,
    projected_residual_risk: 20.5,
    total_risk_reduction: 48.0,
    actions,
    generated_at: new Date().toISOString(),
  };
}

// ── Control Plane Status ─────────────────────────────────────────────────────

const KILL_SWITCH_KEY = 'argolock_kill_switch_active';

export function getLocalControlPlaneStatus(): ControlPlaneStatus {
  let killSwitch = false;
  try {
    killSwitch = localStorage.getItem(KILL_SWITCH_KEY) === 'true';
  } catch (_) {}

  return {
    global_kill_switch_active: killSwitch,
    terminated_mission_count: killSwitch ? 1 : 0,
    enforced_gates: ['Scope Gate', 'Safe-PoC Gate', 'Destructive Payload Gate', 'Approval Gate'],
    destructive_pattern_count: 28,
    status: killSwitch ? 'EMERGENCY_HALTED' : 'ACTIVE_ENFORCING',
  };
}

export function setLocalKillSwitch(active: boolean): ControlPlaneStatus {
  try {
    localStorage.setItem(KILL_SWITCH_KEY, active ? 'true' : 'false');
  } catch (_) {}
  return getLocalControlPlaneStatus();
}

// ── VAPT Center Fallbacks ────────────────────────────────────────────────────

const VAPT_AUTH_KEY = 'argolock_vapt_authorizations';
const VAPT_APPROVALS_KEY = 'argolock_vapt_approvals';

export function getLocalAuthorizations(): any[] {
  try {
    const raw = localStorage.getItem(VAPT_AUTH_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch (_) {}

  const defaults = [
    {
      asset_id: 'asset-nptel-01',
      hostname_or_ip: 'https://onlinecourses.nptel.ac.in',
      owner: 'Security Ops (VAPT Team)',
      authorization_status: 'authorized',
      scope: 'onlinecourses.nptel.ac.in',
      permitted_ports: [80, 443, 8080],
      permitted_services: ['http', 'https'],
      assessment_id: 'assess-primary',
      approval_reference: 'AUTH-VAPT-2026-NPTEL',
      created_at: new Date(Date.now() - 86400000).toISOString(),
    },
    {
      asset_id: 'asset-scanme-02',
      hostname_or_ip: 'http://scanme.nmap.org',
      owner: 'Fyodor / Nmap Project',
      authorization_status: 'authorized',
      scope: 'scanme.nmap.org',
      permitted_ports: [22, 80, 443],
      permitted_services: ['ssh', 'http', 'https'],
      assessment_id: 'assess-scanme',
      approval_reference: 'AUTH-VAPT-2026-SCANME',
      created_at: new Date(Date.now() - 172800000).toISOString(),
    },
  ];

  try {
    localStorage.setItem(VAPT_AUTH_KEY, JSON.stringify(defaults));
  } catch (_) {}

  return defaults;
}

export function saveLocalAuthorization(authData: any): any {
  const current = getLocalAuthorizations();
  const newRecord = {
    ...authData,
    asset_id: authData.asset_id || `asset-${Date.now().toString(36)}`,
    authorization_status: 'authorized',
    created_at: new Date().toISOString(),
  };
  const updated = [newRecord, ...current];
  try {
    localStorage.setItem(VAPT_AUTH_KEY, JSON.stringify(updated));
  } catch (_) {}
  return newRecord;
}

export function getLocalApprovals(): any[] {
  try {
    const raw = localStorage.getItem(VAPT_APPROVALS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (_) {}

  const defaults = [
    {
      id: 'app-01',
      action_type: 'Active Exploitation Validation (Level 2)',
      target: 'https://onlinecourses.nptel.ac.in/e-learning',
      requested_by: 'Specialist Agent: SQLMap & Nuclei',
      status: 'pending',
      justification: 'Automated verification of stored injection payload without database mutation.',
      created_at: new Date(Date.now() - 7200000).toISOString(),
    },
  ];

  try {
    localStorage.setItem(VAPT_APPROVALS_KEY, JSON.stringify(defaults));
  } catch (_) {}

  return defaults;
}

export function updateLocalApproval(id: string, newStatus: 'approved' | 'rejected', notes?: string): any {
  const current = getLocalApprovals();
  let updatedRecord: any = null;
  const updated = current.map(item => {
    if (item.id === id) {
      updatedRecord = {
        ...item,
        status: newStatus,
        decision_notes: notes || `Marked ${newStatus} by Operator`,
        decided_at: new Date().toISOString(),
      };
      return updatedRecord;
    }
    return item;
  });
  try {
    localStorage.setItem(VAPT_APPROVALS_KEY, JSON.stringify(updated));
  } catch (_) {}
  return updatedRecord || { id, status: newStatus };
}

// ── System Status Fallbacks ──────────────────────────────────────────────────

export function getDefaultSystemAgents(): SystemAgentsResponse {
  return {
    active_provider: 'OpenAI',
    active_model: 'gpt-4o',
    provider_configured: true,
    openai_configured: true,
    claude_configured: true,
    ollama_configured: true,
    agents: [
      {
        id: 'vulnerability_agent',
        name: 'Vulnerability Agent',
        role: 'Parser & Classifier',
        description: 'Analyzes raw output from scanners (Nuclei, Nmap, Nikto, etc.) and maps them to standard vulnerability titles, CVE references, and OWASP categories.',
        status: 'active',
        prompt_file: 'vulnerability_analysis.txt',
      },
      {
        id: 'remediation_agent',
        name: 'Remediation Agent',
        role: 'Fix Advisor',
        description: 'Formulates customized, step-by-step remediation plans and writes secure coding examples (Python, JS, Java, etc.) to resolve vulnerabilities.',
        status: 'active',
        prompt_file: 'remediation_advice.txt',
      },
      {
        id: 'risk_scoring_agent',
        name: 'Risk Scoring Agent',
        role: 'CVSS Calculator',
        description: 'Evaluates the exploitability and impact of vulnerabilities to assign accurate CVSS scores and threat severity levels.',
        status: 'active',
        prompt_file: 'risk_scoring.txt',
      },
      {
        id: 'report_agent',
        name: 'Report Agent',
        role: 'Executive Summarizer',
        description: 'Generates executive summaries, compiles raw technical details into structured chapters, and calculates overall security postures.',
        status: 'active',
        prompt_file: 'report_generation.txt',
      },
    ],
  };
}

export function getDefaultSystemTools(): SystemToolsResponse {
  return {
    execution_mode: 'subprocess',
    tools: [
      { id: 'subfinder', name: 'Subfinder', phase: 'Reconnaissance', description: 'Discovers active subdomains using passive OSINT sources.', binary: 'subfinder', execution_mode: 'subprocess', docker_image: null, status: 'available', binary_path: '/usr/local/bin/subfinder', fallback_implemented: true },
      { id: 'amass', name: 'Amass', phase: 'Reconnaissance', description: 'Performs DNS mapping and OSINT-based subdomain enumeration.', binary: 'amass', execution_mode: 'subprocess', docker_image: null, status: 'available', binary_path: '/usr/local/bin/amass', fallback_implemented: true },
      { id: 'naabu', name: 'Naabu', phase: 'Reconnaissance', description: 'Fast port scanner using TCP/UDP SYN probes.', binary: 'naabu', execution_mode: 'subprocess', docker_image: null, status: 'available', binary_path: '/usr/local/bin/naabu', fallback_implemented: true },
      { id: 'nmap', name: 'Nmap', phase: 'Reconnaissance', description: 'Standard port scanner, service detection, and scripting engine.', binary: 'nmap', execution_mode: 'subprocess', docker_image: 'instrumentisto/nmap:latest', status: 'available', binary_path: '/usr/bin/nmap', fallback_implemented: true },
      { id: 'httpx_probe', name: 'httpx-probe', phase: 'Reconnaissance', description: 'HTTP probing tool to identify web technologies, titles, and live endpoints.', binary: 'httpx', execution_mode: 'subprocess', docker_image: null, status: 'available', binary_path: '/usr/local/bin/httpx', fallback_implemented: true },
      { id: 'whatweb', name: 'WhatWeb', phase: 'Reconnaissance', description: 'Technology fingerprinting of content management systems, plugins, and servers.', binary: 'whatweb', execution_mode: 'subprocess', docker_image: null, status: 'fallback', binary_path: null, fallback_implemented: true },
      { id: 'nuclei', name: 'Nuclei', phase: 'Vulnerability Scanning', description: 'Fast, template-based vulnerability scanner for web targets.', binary: 'nuclei', execution_mode: 'subprocess', docker_image: 'projectdiscovery/nuclei:latest', status: 'available', binary_path: '/usr/local/bin/nuclei', fallback_implemented: true },
      { id: 'nikto', name: 'Nikto', phase: 'Vulnerability Scanning', description: 'Scans web servers for outdated software, common misconfigurations, and dangerous paths.', binary: 'nikto', execution_mode: 'subprocess', docker_image: 'frapsoft/nikto:latest', status: 'available', binary_path: null, fallback_implemented: true },
      { id: 'dalfox', name: 'Dalfox', phase: 'Vulnerability Scanning', description: 'Detects Cross-Site Scripting (XSS) vulnerabilities via active injection.', binary: 'dalfox', execution_mode: 'subprocess', docker_image: null, status: 'available', binary_path: null, fallback_implemented: true },
      { id: 'zap', name: 'OWASP ZAP', phase: 'Vulnerability Scanning', description: 'Orchestrates active and passive vulnerability analysis using OWASP ZAP API.', binary: 'zap-api', execution_mode: 'subprocess', docker_image: null, status: 'available', binary_path: 'http://localhost:8080', fallback_implemented: true },
      { id: 'sqlmap', name: 'SQLmap', phase: 'Exploitation', description: 'Automated SQL injection detection and database takeover tool.', binary: 'sqlmap', execution_mode: 'subprocess', docker_image: 'paoloo/sqlmap:latest', status: 'available', binary_path: '/sqlmap/sqlmap.py', fallback_implemented: true },
    ],
  };
}
