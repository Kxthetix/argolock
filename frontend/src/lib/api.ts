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

// ── HTTP Client ───────────────────────────────────────────────────────────────

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem('auth_token');
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

