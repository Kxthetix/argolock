/**
 * Test fixtures for V1.7 platform features.
 * EXCLUDED from production builds — test use only.
 */
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
} from '../../lib/api';

export function getFixtureMissions(): Mission[] {
  return [
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
}

export function getFixtureCapabilityGraph(scanId = 'test-scan-1', target = 'https://onlinecourses.nptel.ac.in'): CapabilityGraph {
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
  ];

  const edges = [
    {
      source_id: 'cap-01',
      target_id: 'cap-02',
      transition_vulnerability: 'Missing Security Headers & Clickjacking',
      transition_confidence: 0.92,
      evidence_hash: 'sha256:e0192a88bf00',
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

export function getFixtureCyberRisk(scanId = 'test-scan-1'): CyberRiskQuantification {
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

export function getFixtureInvestmentPlan(scanId = 'test-scan-1'): InvestmentPlan {
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

export function getFixtureControlPlaneStatus(): ControlPlaneStatus {
  return {
    global_kill_switch_active: false,
    terminated_mission_count: 0,
    enforced_gates: ['Scope Gate', 'Safe-PoC Gate', 'Destructive Payload Gate', 'Approval Gate'],
    destructive_pattern_count: 28,
    status: 'ACTIVE_ENFORCING',
  };
}

export function getFixtureSystemAgents(): SystemAgentsResponse {
  return {
    active_provider: 'OpenAI',
    active_model: 'gpt-4o',
    provider_configured: true,
    openai_configured: true,
    claude_configured: true,
    ollama_configured: true,
    agents: [],
  };
}

export function getFixtureSystemTools(): SystemToolsResponse {
  return {
    execution_mode: 'subprocess',
    tools: [],
  };
}
