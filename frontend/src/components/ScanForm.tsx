import React, { useState } from 'react';
import { api, CreateScanRequest } from '../lib/api';
import { Shield, AlertTriangle, Target, Settings, Zap, ChevronRight } from 'lucide-react';

interface Props {
  onCreated: (scanId: string) => void;
}

export function ScanForm({ onCreated }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [target, setTarget] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [authNote, setAuthNote] = useState('');
  const [enableExploit, setEnableExploit] = useState(false);
  const [nucleiSeverity, setNucleiSeverity] = useState(['critical', 'high', 'medium']);
  const [scanName, setScanName] = useState('');

  const toggleSeverity = (sev: string) => {
    setNucleiSeverity(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) { setError('Target is required'); return; }
    if (!authorized) { setError('You must confirm authorization to scan this target'); return; }

    setError('');
    setLoading(true);

    try {
      const req: CreateScanRequest = {
        name: scanName || undefined,
        scope: {
          target: target.trim(),
          authorized,
          authorization_note: authNote || undefined,
        },
        config: {
          safe_mode: true,
          enable_exploitation: enableExploit,
          nuclei_severity: nucleiSeverity,
        },
      };

      const res = await api.scans.create(req);
      onCreated(res.scan_id);
    } catch (err: any) {
      setError(err.message || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* Target */}
      <div className="form-group">
        <label className="form-label">
          <Target size={12} style={{ display: 'inline', marginRight: 6 }} />
          Target
        </label>
        <input
          id="scan-target"
          className="form-input"
          type="text"
          placeholder="example.com  /  192.168.1.1  /  192.168.1.0/24"
          value={target}
          onChange={e => setTarget(e.target.value)}
          required
        />
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
          Accepts domain names, IP addresses, or CIDR ranges
        </div>
      </div>

      {/* Scan Name */}
      <div className="form-group">
        <label className="form-label">Scan Name (optional)</label>
        <input
          className="form-input"
          type="text"
          placeholder="e.g. Q2 Bug Bounty Assessment"
          value={scanName}
          onChange={e => setScanName(e.target.value)}
        />
      </div>

      {/* Authorization */}
      <div className="form-group">
        <label className="form-label">
          <Shield size={12} style={{ display: 'inline', marginRight: 6 }} />
          Authorization
        </label>
        <label className="form-checkbox" htmlFor="auth-confirm">
          <input
            id="auth-confirm"
            type="checkbox"
            checked={authorized}
            onChange={e => setAuthorized(e.target.checked)}
          />
          <div>
            <div style={{ fontWeight: 600, fontSize: 13 }}>
              I confirm I have authorization to scan this target
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 2 }}>
              I own this system or have explicit written permission to perform security testing.
              Unauthorized scanning is illegal and unethical.
            </div>
          </div>
        </label>
      </div>

      {authorized && (
        <div className="form-group">
          <label className="form-label">Authorization Reference (optional)</label>
          <input
            className="form-input"
            type="text"
            placeholder="e.g. HackerOne Bug Bounty Program, Internal security assessment"
            value={authNote}
            onChange={e => setAuthNote(e.target.value)}
          />
        </div>
      )}

      {/* Advanced Settings Toggle */}
      <button
        type="button"
        onClick={() => setShowAdvanced(!showAdvanced)}
        style={{
          background: 'none', border: 'none', color: 'var(--primary-light)',
          fontSize: 13, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
          marginBottom: 16, padding: 0,
        }}
      >
        <Settings size={14} />
        Advanced Settings
        <ChevronRight
          size={14}
          style={{ transform: showAdvanced ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }}
        />
      </button>

      {showAdvanced && (
        <div style={{
          background: 'var(--bg-elevated)', borderRadius: 'var(--radius)',
          padding: 20, marginBottom: 20, border: '1px solid var(--border)',
        }}>
          {/* Nuclei Severity */}
          <div className="form-group">
            <label className="form-label">Nuclei Severity Filter</label>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => toggleSeverity(sev)}
                  className={`badge badge-${sev}`}
                  style={{
                    cursor: 'pointer',
                    opacity: nucleiSeverity.includes(sev) ? 1 : 0.3,
                    border: 'none', padding: '6px 14px', fontSize: 12,
                  }}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Exploitation */}
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-checkbox" htmlFor="enable-exploit">
              <input
                id="enable-exploit"
                type="checkbox"
                checked={enableExploit}
                onChange={e => setEnableExploit(e.target.checked)}
              />
              <div>
                <div style={{ fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
                  Enable Exploitation (SQLmap safe mode)
                  <span className="badge badge-high" style={{ fontSize: 9 }}>Advanced</span>
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 2 }}>
                  Run SQLmap (level=1, risk=1, boolean-only) on discovered endpoints
                </div>
              </div>
            </label>
          </div>
        </div>
      )}

      {error && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: 12,
          background: 'var(--sev-critical-bg)', border: '1px solid rgba(255,59,48,0.3)',
          borderRadius: 'var(--radius-sm)', color: 'var(--sev-critical)', fontSize: 13,
          marginBottom: 16,
        }}>
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      <button
        id="start-scan-btn"
        type="submit"
        className="btn btn-primary w-full btn-lg"
        disabled={loading}
      >
        {loading ? (
          <>
            <svg className="animate-spin" width={18} height={18} viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" strokeOpacity="0.3" />
              <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
            </svg>
            Starting Scan...
          </>
        ) : (
          <>
            <Zap size={18} />
            Launch VAPT Scan
          </>
        )}
      </button>
    </form>
  );
}
