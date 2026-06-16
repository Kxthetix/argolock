// ─────────────────────────────────────────────────────────────────────────────
// API client with automatic demo/mock fallback.
// When VITE_API_URL is not set and the backend is unreachable the app
// transparently serves realistic mock data so every UI feature works.
// ─────────────────────────────────────────────────────────────────────────────

import { DEMO_SCANS, DEMO_FINDINGS, DEMO_REPORTS } from './mockData';

const API_BASE = import.meta.env.VITE_API_URL || '/api';

// ── Demo mode detection ───────────────────────────────────────────────────────
// Treat the app as being in "demo mode" when there is no VITE_API_URL env var
// (i.e., plain Vercel / static deployment without a backend).
const IS_DEMO = !import.meta.env.VITE_API_URL;

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

// ── Demo scan state (persisted in sessionStorage) ────────────────────────────
function getDemoScans(): Scan[] {
  try {
    const raw = sessionStorage.getItem('argolock_demo_scans');
    if (raw) return JSON.parse(raw) as Scan[];
  } catch (_) {}
  return [...DEMO_SCANS];
}

function saveDemoScans(scans: Scan[]) {
  try { sessionStorage.setItem('argolock_demo_scans', JSON.stringify(scans)); } catch (_) {}
}

let _demoScanCounter = 100;

// ── Real HTTP client ──────────────────────────────────────────────────────────
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

// ── Simulated async delay ─────────────────────────────────────────────────────
function delay(ms: number) { return new Promise(r => setTimeout(r, ms)); }

// ── Mock API implementation ───────────────────────────────────────────────────
const mockApi = {
  scans: {
    create: async (data: CreateScanRequest) => {
      await delay(900);
      const newId = `scan-demo-${++_demoScanCounter}`;
      const now = new Date().toISOString();
      const newScan: Scan = {
        id: newId,
        name: data.name || `Scan of ${data.scope.target}`,
        scope: data.scope,
        config: data.config || {},
        status: 'pending',
        progress_percent: 0,
        created_at: now,
        finding_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
      };
      const scans = getDemoScans();
      scans.unshift(newScan);
      saveDemoScans(scans);

      // Simulate the scan progressing over time
      _simulateScanProgress(newId);

      return { scan_id: newId, status: 'pending', message: 'Scope validated. Scan queued. (Demo mode)' };
    },

    list: async (skip = 0, limit = 20) => {
      await delay(200);
      const all = getDemoScans();
      return { scans: all.slice(skip, skip + limit), skip, limit };
    },

    get: async (id: string) => {
      await delay(150);
      const scans = getDemoScans();
      const scan = scans.find(s => s.id === id);
      if (!scan) throw new Error('Scan not found');
      return scan;
    },

    findings: async (id: string, severity?: string) => {
      await delay(200);
      let findings = DEMO_FINDINGS.filter(f => f.scan_id === id);
      if (severity) findings = findings.filter(f => f.severity === severity);
      return { findings, total: findings.length };
    },

    cancel: async (id: string) => {
      await delay(300);
      const scans = getDemoScans();
      const scan = scans.find(s => s.id === id);
      if (scan) {
        scan.status = 'cancelled';
        scan.completed_at = new Date().toISOString();
        saveDemoScans(scans);
      }
      return { message: 'Scan cancelled (Demo mode)' };
    },
  },

  findings: {
    list: async (params?: { severity?: string; skip?: number; limit?: number }) => {
      await delay(200);
      let findings = [...DEMO_FINDINGS];
      if (params?.severity) findings = findings.filter(f => f.severity === params.severity);
      const skip = params?.skip || 0;
      const limit = params?.limit || 50;
      return { findings: findings.slice(skip, skip + limit), total: findings.length };
    },
    get: async (id: string) => {
      await delay(150);
      const f = DEMO_FINDINGS.find(f => f.id === id);
      if (!f) throw new Error('Finding not found');
      return f;
    },
  },

  reports: {
    get: async (scanId: string) => {
      await delay(250);
      const r = DEMO_REPORTS[scanId];
      if (!r) throw new Error('Report not found');
      return r;
    },
    downloadPdfUrl: (scanId: string) => `${API_BASE}/reports/${scanId}/download/pdf`,
    downloadJsonUrl: (scanId: string) => `${API_BASE}/reports/${scanId}/download/json`,
    downloadPdfAbsUrl: (scanId: string) => `http://localhost:8000/api/reports/${scanId}/download/pdf`,
    downloadJsonAbsUrl: (scanId: string) => `http://localhost:8000/api/reports/${scanId}/download/json`,
  },

  health: async () => {
    await delay(100);
    return { status: 'demo' };
  },
};

// ── Scan progress simulator ───────────────────────────────────────────────────
function _simulateScanProgress(scanId: string) {
  const phases = ['recon', 'scanning', 'ai_analysis', 'reporting', 'completed'] as const;
  const phaseDurations = [8000, 15000, 6000, 4000, 0]; // ms per phase
  const phaseTargetProgress = [20, 75, 90, 98, 100];

  let phaseIndex = 0;

  function tick() {
    const scans = getDemoScans();
    const scan = scans.find(s => s.id === scanId);
    if (!scan || scan.status === 'cancelled') return;

    const targetPhase = phases[phaseIndex];
    const targetPct = phaseTargetProgress[phaseIndex];

    scan.status = phaseIndex < phases.length - 1 ? targetPhase : 'completed';
    scan.current_phase = targetPhase;

    // Advance progress smoothly
    const step = Math.min(targetPct - scan.progress_percent, 5);
    scan.progress_percent = Math.min(scan.progress_percent + Math.max(step, 1), targetPct);

    if (phaseIndex === phases.length - 1) {
      // Completed
      scan.status = 'completed';
      scan.progress_percent = 100;
      scan.completed_at = new Date().toISOString();
      scan.finding_count = 3;
      scan.high_count = 1;
      scan.medium_count = 2;
      scan.tool_results = {
        nmap: { status: 'completed', duration_seconds: 32.1 },
        nuclei: { status: 'completed', duration_seconds: 210.4 },
        ai_analysis: { status: 'completed', duration_seconds: 14.8 },
      };
      saveDemoScans(scans);
      return;
    }

    saveDemoScans(scans);

    if (scan.progress_percent >= targetPct) {
      phaseIndex++;
      setTimeout(tick, phaseDurations[phaseIndex] / 10);
    } else {
      setTimeout(tick, 800);
    }
  }

  // Start after a brief pending delay
  setTimeout(tick, 2000);
}

// ── Public API (auto-selects real or mock) ────────────────────────────────────
export const api = IS_DEMO ? {
  scans: {
    create: (data: CreateScanRequest) => mockApi.scans.create(data),
    list: (skip = 0, limit = 20) => mockApi.scans.list(skip, limit),
    get: (id: string) => mockApi.scans.get(id),
    findings: (id: string, severity?: string) => mockApi.scans.findings(id, severity),
    cancel: (id: string) => mockApi.scans.cancel(id),
  },
  findings: {
    list: (params?: { severity?: string; skip?: number; limit?: number }) => mockApi.findings.list(params),
    get: (id: string) => mockApi.findings.get(id),
  },
  reports: {
    get: (scanId: string) => mockApi.reports.get(scanId),
    downloadPdfUrl: (scanId: string) => mockApi.reports.downloadPdfUrl(scanId),
    downloadJsonUrl: (scanId: string) => mockApi.reports.downloadJsonUrl(scanId),
    downloadPdfAbsUrl: (scanId: string) => mockApi.reports.downloadPdfAbsUrl(scanId),
    downloadJsonAbsUrl: (scanId: string) => mockApi.reports.downloadJsonAbsUrl(scanId),
  },
  health: () => mockApi.health(),
} : {
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
    downloadPdfAbsUrl: (scanId: string) => `http://localhost:8000/api/reports/${scanId}/download/pdf`,
    downloadJsonAbsUrl: (scanId: string) => `http://localhost:8000/api/reports/${scanId}/download/json`,
  },
  health: () => request<{ status: string }>('/health'),
};

// Export demo mode flag and API base path for UI banners / authentication
export { IS_DEMO, API_BASE };
