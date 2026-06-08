// Use relative path so requests go through the Vite dev server proxy → avoids CORS.
// In production, set VITE_API_URL to the absolute backend URL.
const API_BASE = import.meta.env.VITE_API_URL || '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
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
  error?: string;
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

// ── Scan APIs ─────────────────────────────────────────────────────────────────

export const api = {
  scans: {
    create: (data: CreateScanRequest) =>
      request<{ scan_id: string; status: string; message: string }>('/scans', {
        method: 'POST',
        body: JSON.stringify(data),
      }),

    list: (skip = 0, limit = 20) =>
      request<{ scans: Scan[]; skip: number; limit: number }>(`/scans?skip=${skip}&limit=${limit}`),

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
    downloadPdfUrl: (scanId: string) => `${API_BASE}/reports/${scanId}/download/pdf`,
    downloadJsonUrl: (scanId: string) => `${API_BASE}/reports/${scanId}/download/json`,
    // Absolute URL for direct download links (bypass proxy for file downloads)
    downloadPdfAbsUrl: (scanId: string) => `http://localhost:8000/api/reports/${scanId}/download/pdf`,
    downloadJsonAbsUrl: (scanId: string) => `http://localhost:8000/api/reports/${scanId}/download/json`,
  },

  health: () => request<{ status: string }>('/health'),
};
