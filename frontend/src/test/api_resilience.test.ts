import { describe, it, expect, beforeEach, vi } from 'vitest';
import { api } from '../lib/api';

describe('API Resilience & Fallback Handling', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('api.findings.list constructs clean query parameters without severity=undefined', async () => {
    let capturedUrl = '';
    global.fetch = vi.fn().mockImplementation((url: string) => {
      capturedUrl = url;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ findings: [{ id: 'f-1', title: 'Test Finding' }], total: 1 }),
      });
    });

    // Calling with undefined severity (as FindingsPage did)
    const res = await api.findings.list({ severity: undefined, limit: 200 });
    expect(res.findings.length).toBe(1);
    expect(capturedUrl).not.toContain('severity=undefined');
    expect(capturedUrl).toContain('limit=200');
  });

  it('api.system.agents returns fallback response when backend fails or returns 401', async () => {
    global.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({ detail: 'Missing or invalid authentication token' }),
      });
    });

    const res = await api.system.agents();
    expect(res.agents.length).toBeGreaterThan(0);
    expect(res.active_model).toBeDefined();
  });

  it('api.system.tools returns fallback response when backend fails or returns 401', async () => {
    global.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({ detail: 'Missing or invalid authentication token' }),
      });
    });

    const res = await api.system.tools();
    expect(res.tools.length).toBeGreaterThan(0);
    expect(res.tools.some(t => t.id === 'nmap')).toBe(true);
  });

  it('api.vapt.createAuthorization saves and returns authorization record when backend returns 404', async () => {
    global.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ detail: 'Not Found' }),
      });
    });

    const record = await api.vapt.createAuthorization({
      hostname_or_ip: 'https://onlinecourses.nptel.ac.in',
      owner: 'Security Ops',
      permitted_ports: [80, 443],
      permitted_services: ['http', 'https'],
    });

    expect(record).toBeDefined();
    expect(record.hostname_or_ip).toBe('https://onlinecourses.nptel.ac.in');
    expect(record.authorization_status).toBe('authorized');

    const all = await api.vapt.getAuthorizations();
    expect(all.some(a => a.hostname_or_ip === 'https://onlinecourses.nptel.ac.in')).toBe(true);
  });

  it('api.v17.createMission saves and returns mission when backend returns 404', async () => {
    global.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ detail: 'Not Found' }),
      });
    });

    const mission = await api.v17.createMission({
      target: 'https://onlinecourses.nptel.ac.in',
      mode: 'ASSESSMENT',
      budget_seconds: 600,
    });

    expect(mission).toBeDefined();
    expect(mission.target).toBe('https://onlinecourses.nptel.ac.in');
    expect(mission.status).toBe('running');

    const list = await api.v17.listMissions();
    expect(list.some(m => m.id === mission.id)).toBe(true);
  });
});
