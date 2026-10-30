import { describe, it, expect, beforeEach, vi } from 'vitest';
import { api } from '../lib/api';

describe('API Resilience & Fallback Handling', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('api.findings.list constructs clean query parameters without severity=undefined', async () => {
    let capturedUrl = '';
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      capturedUrl = url;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ findings: [{ id: 'f-1', title: 'Test Finding' }], total: 1 }),
      } as Response);
    });

    // Calling with undefined severity (as FindingsPage did)
    const res = await api.findings.list({ severity: undefined, limit: 200 });
    expect(res.findings.length).toBe(1);
    expect(capturedUrl).not.toContain('severity=undefined');
    expect(capturedUrl).toContain('limit=200');
  });

  it('api.system.agents fails closed and throws when backend returns 401/error', async () => {
    globalThis.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({ detail: 'Missing or invalid authentication token' }),
      } as Response);
    });

    await expect(api.system.agents()).rejects.toThrow('Missing or invalid authentication token');
  });

  it('api.system.tools fails closed and throws when backend returns 401/error', async () => {
    globalThis.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({ detail: 'Missing or invalid authentication token' }),
      } as Response);
    });

    await expect(api.system.tools()).rejects.toThrow('Missing or invalid authentication token');
  });

  it('api.vapt.createAuthorization fails closed without localStorage fallbacks when backend fails', async () => {
    globalThis.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ detail: 'Target authorization service unavailable' }),
      } as Response);
    });

    await expect(api.vapt.createAuthorization({
      hostname_or_ip: 'https://onlinecourses.nptel.ac.in',
      owner: 'Security Ops',
      permitted_ports: [80, 443],
      permitted_services: ['http', 'https'],
    })).rejects.toThrow('Target authorization service unavailable');

    expect(localStorage.getItem('argolock_vapt_authorizations')).toBeNull();
  });

  it('api.v17.createMission fails closed and throws when backend returns error without silent localStorage mocks', async () => {
    globalThis.fetch = vi.fn().mockImplementation(() => {
      return Promise.resolve({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        json: async () => ({ detail: 'Mission orchestration service unavailable' }),
      } as Response);
    });

    await expect(api.v17.createMission({
      target: 'https://onlinecourses.nptel.ac.in',
      mode: 'ASSESSMENT',
      budget_seconds: 600,
    })).rejects.toThrow('Mission orchestration service unavailable');

    expect(localStorage.getItem('argolock_v17_missions')).toBeNull();
  });
});
