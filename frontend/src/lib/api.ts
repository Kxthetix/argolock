// ─────────────────────────────────────────────────────────────────────────────
// ArgoLock API Client — Production HTTP client for all backend communication.
// ─────────────────────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL || '/api';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ScanScope {
  target: string;
  authorized: boolean;
  authorization_note?: string;
  excluded_paths?: string[];
  max_depth?: number;
}

export interface ScanConfig {
  phases?: string[];
  safe_mode?: boolean;
  enable_exploitation?: boolean;
  nuclei_severity?: string[];
  nmap_ports?: string;
  timeout_minutes?: number;
}

export interface CreateScanRequest {
  scope: ScanScope;
  config?: ScanConfig;
  name?: string;
}

export interface Scan {
  id: string;
  name: string;
  scope: ScanScope;
  config: ScanConfig;
  status: string;
  current_phase?: string;
  progress_percent: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count?: number;
  tool_results?: Record<string, any>;
  exploitation_stages?: Record<string, ExploitationStage>;
  error?: string;
}

export interface ExploitationStage {
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  started_at?: string;
  completed_at?: string;
  summary?: string;
  findings_count: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  owasp_category: string;
  cvss_score: number;
  affected_endpoint: string;
  affected_parameter?: string;
  tool_source: string;
  confirmed?: boolean;
  false_positive?: boolean;
  poc?: {
    request?: string;
    response?: string;
    payload?: string;
    reproduction_steps?: string[];
  };
  remediation?: {
    root_cause?: string;
    fix_steps?: string[];
    secure_code_example?: string;
    references?: string[];
  };
  tags?: string[];
  cve_ids?: string[];
  discovered_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  format: string;
  generated_at: string;
  pdf_path?: string;
  json_path?: string;
  executive_summary?: string;
  total_findings: number;
  risk_score: number;
  risk_rating: string;
}

export interface SystemAgent {
  id: string;
  name: string;
  role: string;
  description: string;
  status: 'active' | 'inactive';
  prompt_file: string;
}

export interface SystemAgentsResponse {
  active_provider: string;
  active_model: string;
  provider_configured: boolean;
  openai_configured: boolean;
  claude_configured: boolean;
  ollama_configured: boolean;
  agents: SystemAgent[];
}

export interface SystemTool {
  id: string;
  name: string;
  phase: string;
  description: string;
  binary: string;
  execution_mode: 'docker' | 'subprocess';
  docker_image: string | null;
  status: 'available' | 'fallback' | 'missing';
  binary_path: string | null;
  fallback_implemented: boolean;
}

export interface SystemToolsResponse {
  execution_mode: string;
  tools: SystemTool[];
}

// ── V1.7 Interfaces ──────────────────────────────────────────────────────────

export type MissionMode = 'DISCOVERY' | 'ASSESSMENT' | 'VALIDATION' | 'CONTINUOUS';

export interface Mission {
  id: string;
  name: string;
  target: string;
  mode: MissionMode;
  status: string;
  current_phase: string;
  progress_percent: number;
  budget_seconds: number;
  scope_whitelist: string[];
  scope_blacklist: string[];
  active_agent_count: number;
  findings_count: number;
  verified_count: number;
  capabilities_count: number;
  risk_score: number;
  created_at: string;
  completed_at?: string;
}

export interface AgentProfile {
  id: string;
  code: string;
  name: string;
  category: string;
  description: string;
  tools: string[];
  status: string;
  capabilities: string[];
  confidence_weight: number;
}

export interface CapabilityNode {
  id: string;
  name: string;
  description: string;
  target_asset: string;
  finding_id?: string;
  prerequisite_node_ids?: string[];
  confidence: number;
  terminal_impact: boolean;
  evidence_hash?: string;
  discovered_at: string;
}

export interface CapabilityEdge {
  source_id: string;
  target_id: string;
  transition_vulnerability: string;
  transition_confidence: number;
  evidence_hash: string;
}

export interface AttackChain {
  id: string;
  scan_id: string;
  title: string;
  entry_point: string;
  terminal_impact: string;
  path_nodes: CapabilityNode[];
  overall_confidence: number;
  severity: string;
  created_at: string;
}

export interface CapabilityGraph {
  scan_id: string;
  target: string;
  total_nodes: number;
  total_edges: number;
  nodes: CapabilityNode[];
  edges: CapabilityEdge[];
  attack_chains: AttackChain[];
  generated_at: string;
}

export interface CyberRiskQuantification {
  scan_id: string;
  score: number;
  rating: string;
  severity_factor: number;
  exploitability_factor: number;
  asset_criticality_factor: number;
  exposure_factor: number;
  business_impact_factor: number;
  threat_relevance_factor: number;
  confidence_factor: number;
  calculation_breakdown: Record<string, any>;
  calculated_at: string;
}

export interface RemediationAction {
  id: string;
  finding_id?: string;
  title: string;
  recommended_control: string;
  estimated_cost: string;
  cost_index: number;
  risk_reduction_points: number;
  residual_risk_points: number;
  roi_score: number;
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  effort_hours: number;
  compliance_mappings: string[];
}

export interface InvestmentPlan {
  scan_id: string;
  initial_risk_score: number;
  projected_residual_risk: number;
  total_risk_reduction: number;
  actions: RemediationAction[];
  generated_at: string;
}

export interface ControlPlaneStatus {
  global_kill_switch_active: boolean;
  terminated_mission_count: number;
  enforced_gates: string[];
  destructive_pattern_count: number;
  status: string;
}

// ── Auth Helpers ──────────────────────────────────────────────────────────────

export function isTokenExpired(token: string | null): boolean {
  if (!token) return true;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1]));
    if (!payload.exp) return false;
    // Check expiration with a 30-second clock skew buffer
    return Date.now() >= (payload.exp * 1000) - 30000;
  } catch {
    return false;
  }
}

export function getStoredToken(): string | null {
  const token = localStorage.getItem('auth_token');
  if (!token) return null;
  if (isTokenExpired(token)) {
    clearAuthSession();
    return null;
  }
  return token;
}

export function clearAuthSession(): void {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('auth_email');
}

export function handleSessionExpired(): void {
  clearAuthSession();
}

// ── HTTP Client ───────────────────────────────────────────────────────────────

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, {
    headers,
    ...options,
  });
  if (!res.ok) {
    let errMsg = res.statusText;
    try {
      const body = await res.json();
      errMsg = body.detail ?? body.message ?? body.error ?? JSON.stringify(body);
    } catch (_) {}

    if (res.status === 401) {
      clearAuthSession();
    }

    throw new Error(errMsg);
  }
  return res.json();
}

// ── Auth API ──────────────────────────────────────────────────────────────────

export const authApi = {
  login: (email: string, password: string) =>
    request<{ access_token: string; token_type: string; email: string }>(
      '/auth/login',
      { method: 'POST', body: JSON.stringify({ email, password }) }
    ),

  register: (email: string, password: string, name: string) =>
    request<{ access_token: string; token_type: string; email: string }>(
      '/auth/register',
      { method: 'POST', body: JSON.stringify({ email, password, name }) }
    ),

  sendOtp: (email: string) =>
    request<{ message: string }>('/auth/otp/send', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  verifyOtp: (email: string, code: string) =>
    request<{ access_token: string; token_type: string; email: string }>(
      '/auth/otp/verify',
      { method: 'POST', body: JSON.stringify({ email, code }) }
    ),

  googleUrl: () => `${API_BASE}/auth/google`,
  githubUrl: () => `${API_BASE}/auth/github`,

  me: () => request<any>('/auth/me'),
};

// ── Scans API ─────────────────────────────────────────────────────────────────

// ── Findings API ──────────────────────────────────────────────────────────────

// ── Reports API ───────────────────────────────────────────────────────────────

// ── Health API ────────────────────────────────────────────────────────────────

export const api = {
  scans: {
    create: (data: CreateScanRequest) =>
      request<{ scan_id: string; status: string; message: string }>('/scans', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    list: (skip = 0, limit = 20) =>
      request<{ scans: Scan[]; skip: number; limit: number }>(
        `/scans?skip=${skip}&limit=${limit}`
      ),
    get: (id: string) => request<Scan>(`/scans/${id}`),
    findings: (id: string, severity?: string) =>
      request<{ findings: Finding[]; total: number }>(
        `/scans/${id}/findings${severity ? `?severity=${severity}` : ''}`
      ),
    cancel: (id: string) =>
      request<{ message: string }>(`/scans/${id}`, { method: 'DELETE' }),
  },

  findings: {
    list: (params?: { severity?: string; skip?: number; limit?: number }) => {
      const q = new URLSearchParams(params as any).toString();
      return request<{ findings: Finding[]; total: number }>(`/findings?${q}`);
    },
    get: (id: string) => request<Finding>(`/findings/${id}`),
  },

  reports: {
    get: (scanId: string) => request<Report>(`/reports/${scanId}`),
    downloadPdfUrl: (scanId: string) =>
      `${API_BASE}/reports/${scanId}/download/pdf`,
    downloadJsonUrl: (scanId: string) =>
      `${API_BASE}/reports/${scanId}/download/json`,
    downloadPdfAbsUrl: (scanId: string) => {
      const base = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
      return `${base}/reports/${scanId}/download/pdf`;
    },
    downloadJsonAbsUrl: (scanId: string) => {
      const base = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
      return `${base}/reports/${scanId}/download/json`;
    },
  },

  health: () => request<{ status: string }>('/health'),
  system: {
    agents: () => request<SystemAgentsResponse>('/system/agents'),
    tools: () => request<SystemToolsResponse>('/system/tools'),
    clearHistory: () => request<{ status: string; message: string; purged_counts: Record<string, number> }>('/system/clear-history', { method: 'POST' }),
  },
  vapt: {
    getAuthorizations: () => request<any[]>('/vapt/authorizations'),
    createAuthorization: (data: any) =>
      request<any>('/vapt/authorizations', { method: 'POST', body: JSON.stringify(data) }),
    getApprovals: (status?: string) =>
      request<any[]>(`/vapt/approvals${status ? `?status=${status}` : ''}`),
    requestApproval: (data: any) =>
      request<any>('/vapt/approvals', { method: 'POST', body: JSON.stringify(data) }),
    approve: (id: string, notes?: string) =>
      request<any>(`/vapt/approvals/${id}/approve`, { method: 'POST', body: JSON.stringify({ decision_notes: notes }) }),
    reject: (id: string, notes?: string) =>
      request<any>(`/vapt/approvals/${id}/reject`, { method: 'POST', body: JSON.stringify({ decision_notes: notes }) }),
    validateFinding: (findingId: string, testingLevel = 'level_1', approvalId?: string) =>
      request<any>(`/vapt/findings/${findingId}/validate?testing_level=${testingLevel}${approvalId ? `&approval_id=${approvalId}` : ''}`, {
        method: 'POST',
      }),
    getExploitability: (findingId: string) => request<any>(`/vapt/findings/${findingId}/exploitability`),
    getRisk: (findingId: string) => request<any>(`/vapt/risk/${findingId}`),
    getEvidence: (findingId: string) => request<any>(`/vapt/findings/${findingId}/evidence`),
    getRemediationPlan: (findingId: string) => request<any>(`/vapt/findings/${findingId}/remediation`),
    retestFinding: (findingId: string) => request<any>(`/vapt/findings/${findingId}/retest`, { method: 'POST' }),
    getAttackPaths: () => request<any>('/vapt/attack-paths'),
    getMitreMappings: () => request<any[]>('/vapt/mitre-mappings'),
    getToolsHealth: () => request<any[]>('/vapt/tools/health'),
    getAuditTrail: (limit = 50) => request<any[]>(`/vapt/audit?limit=${limit}`),
  },
  v17: {
    listMissions: () => request<Mission[]>('/v1/missions'),
    createMission: (data: { name?: string; target: string; mode: MissionMode; budget_seconds?: number; scope_whitelist?: string[]; scope_blacklist?: string[] }) =>
      request<Mission>('/v1/missions', { method: 'POST', body: JSON.stringify(data) }),
    getMission: (id: string) => request<Mission>(`/v1/missions/${id}`),
    listAgents: (category?: string) =>
      request<{ total_agents: number; categories: string[]; agents: AgentProfile[] }>(`/v1/agents${category ? `?category=${category}` : ''}`),
    getAgent: (codeOrId: string) => request<AgentProfile>(`/v1/agents/${codeOrId}`),
    getCapabilityGraph: (scanId: string) => request<CapabilityGraph>(`/v1/capability-graph/${scanId}`),
    getCyberRisk: (scanId: string, assetCriticality = 1.2, exposure = 1.3) =>
      request<CyberRiskQuantification>(`/v1/risk/${scanId}?asset_criticality=${assetCriticality}&exposure=${exposure}`),
    getInvestmentPlan: (scanId: string) => request<InvestmentPlan>(`/v1/investment/${scanId}`),
    getControlPlaneStatus: () => request<ControlPlaneStatus>('/v1/security-control-plane/status'),
    toggleKillSwitch: (activate: boolean, missionId?: string) =>
      request<any>('/v1/security-control-plane/kill-switch', { method: 'POST', body: JSON.stringify({ activate, mission_id: missionId }) }),
    adversarialValidate: (finding: any) =>
      request<any>('/v1/adversarial-validate', { method: 'POST', body: JSON.stringify(finding) }),
  },
};

// ── Date Utility ─────────────────────────────────────────────────────────────

/**
 * Safely parse ISO date strings from backend APIs.
 * Ensures UTC timestamps missing a timezone designation ('Z') are treated as UTC,
 * preventing local timezone offset shifts (e.g. 5.5 hours skew).
 */
export function parseUtcDate(dateInput?: string | Date | null): Date {
  if (!dateInput) return new Date();
  if (dateInput instanceof Date) return dateInput;
  let s = String(dateInput).trim();
  if (s.includes('T') && !s.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(s)) {
    s += 'Z';
  }
  return new Date(s);
}

// Export API base path for direct URL construction
export { API_BASE };

