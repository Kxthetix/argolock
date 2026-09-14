import React, { useEffect, useState } from 'react';
import { api, clearAuthSession, SystemTool, SystemToolsResponse } from '../lib/api';
import { Activity, CheckCircle, AlertTriangle, XCircle, Terminal, Container, Shield, Info } from 'lucide-react';

export function ToolStatusPage() {
  const [data, setData] = useState<SystemToolsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [purging, setPurging] = useState(false);
  const [confirmPurge, setConfirmPurge] = useState(false);
  const [purgeSuccess, setPurgeSuccess] = useState(false);

  const handlePurgeHistory = async () => {
    setPurging(true);
    try {
      await api.system.clearHistory();
      setPurgeSuccess(true);
      setConfirmPurge(false);
      setTimeout(() => {
        setPurgeSuccess(false);
        window.location.reload();
      }, 2000);
    } catch (err: any) {
      console.error(err);
      alert('Failed to clear history: ' + (err.message || String(err)));
    } finally {
      setPurging(false);
    }
  };

  useEffect(() => {
    const fetchTools = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.system.tools();
        setData(res);
      } catch (err: any) {
        console.error('Failed to fetch tools:', err);
        setError(err.message || 'Failed to fetch security tools status.');
      } finally {
        setLoading(false);
      }
    };
    fetchTools();
  }, []);

  if (loading) {
    return (
      <div className="page-content animate-fadeIn">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="skeleton" style={{ width: 250, height: 36 }} />
            <div className="skeleton" style={{ width: 400, height: 20 }} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="skeleton" style={{ height: 100, borderRadius: 12 }} />
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
            {[1, 2, 3].map(i => (
              <div key={i} className="skeleton" style={{ height: 350, borderRadius: 12 }} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    const isAuthError =
      error.toLowerCase().includes('token') ||
      error.toLowerCase().includes('authentication') ||
      error.toLowerCase().includes('session') ||
      error.toLowerCase().includes('401') ||
      error.toLowerCase().includes('unauthorized');

    return (
      <div className="page-content animate-fadeIn">
        <div className="card" style={{ border: '1px solid var(--sev-critical)', padding: 40, textAlign: 'center', background: 'rgba(255,59,48,0.03)' }}>
          <XCircle className="text-critical" style={{ width: 64, height: 64, marginBottom: 20, filter: 'drop-shadow(0 0 10px rgba(255,59,48,0.2))' }} />
          <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 8 }}>
            {isAuthError ? 'Session Expired' : 'System Communication Error'}
          </h2>
          <p className="text-secondary" style={{ marginBottom: 28, maxWidth: 500, margin: '0 auto 24px' }}>
            {isAuthError
              ? 'Your authentication session has expired or is invalid. Please sign in again to continue.'
              : error}
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
            {isAuthError ? (
              <button
                className="btn btn-primary"
                onClick={() => {
                  clearAuthSession();
                  window.location.href = '/login?expired=true&redirect=%2Ftool-status';
                }}
              >
                Log In Again
              </button>
            ) : (
              <button className="btn btn-outline" onClick={() => window.location.reload()}>
                Retry Connection
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  const tools = data?.tools || [];
  const total = tools.length;
  const available = tools.filter(t => t.status === 'available').length;
  const fallback = tools.filter(t => t.status === 'fallback').length;
  const missing = tools.filter(t => t.status === 'missing').length;

  // Group tools by phase
  const phases = {
    Reconnaissance: tools.filter(t => t.phase === 'Reconnaissance'),
    'Vulnerability Scanning': tools.filter(t => t.phase === 'Vulnerability Scanning'),
    Exploitation: tools.filter(t => t.phase === 'Exploitation'),
  };

  return (
    <div className="page-content animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 style={{ fontSize: 32, fontWeight: 900, display: 'flex', alignItems: 'center', gap: 12, letterSpacing: '-0.5px' }}>
            <Activity className="text-accent" style={{ width: 36, height: 36, filter: 'drop-shadow(0 0 10px rgba(0,212,255,0.3))' }} />
            Tool Status
          </h1>
          <p className="text-secondary mt-2" style={{ fontSize: 15 }}>
            Audit binary installations, execution configs, and Python fallback status across VAPT pipeline stages.
          </p>
        </div>

        {/* Purge button controls */}
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {confirmPurge ? (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', background: 'rgba(255,69,58,0.1)', padding: '6px 12px', borderRadius: 8, border: '1px solid rgba(255,69,58,0.3)' }}>
              <span style={{ fontSize: 12, color: '#ff453a', fontWeight: 600 }}>Confirm Purge All Scan Data?</span>
              <button 
                className="btn btn-danger btn-sm"
                onClick={handlePurgeHistory}
                disabled={purging}
                style={{ padding: '4px 10px', fontSize: 11, background: '#ff453a' }}
              >
                {purging ? 'Purging...' : 'Yes, Delete'}
              </button>
              <button 
                className="btn btn-outline btn-sm" 
                onClick={() => setConfirmPurge(false)}
                disabled={purging}
                style={{ padding: '4px 10px', fontSize: 11, background: 'rgba(255,255,255,0.05)' }}
              >
                Cancel
              </button>
            </div>
          ) : (
            <button 
              className="btn btn-danger btn-sm"
              onClick={() => setConfirmPurge(true)}
              style={{
                background: 'rgba(255,69,58,0.1)',
                border: '1px solid rgba(255,69,58,0.25)',
                color: '#ff453a',
                padding: '8px 16px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Purge Scan History
            </button>
          )}
        </div>
      </div>

      {/* Success Banner */}
      {purgeSuccess && (
        <div style={{
          background: 'rgba(48, 209, 88, 0.1)',
          border: '1px solid rgba(48, 209, 88, 0.3)',
          borderRadius: 8,
          padding: '12px 20px',
          color: '#30d158',
          fontSize: 14,
          fontWeight: 600,
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          gap: 10
        }} className="animate-fadeIn">
          <CheckCircle style={{ width: 18, height: 18 }} />
          <span>All scan histories, findings, and reports have been purged successfully! Refreshing database...</span>
        </div>
      )}

      {/* Stats Cards */}
      <div className="stat-grid" style={{ marginBottom: 32 }}>
        <div className="stat-card" style={{ '--card-accent': 'var(--primary)' } as any}>
          <div className="stat-label">Execution Environment</div>
          <div className="stat-value" style={{ fontSize: 22, padding: '6px 0', textTransform: 'uppercase', color: 'var(--primary-light)', fontWeight: 800 }}>
            {data?.execution_mode || 'Subprocess'}
          </div>
          <div className="stat-sub">Backend run environment config</div>
        </div>

        <div className="stat-card" style={{ '--card-accent': 'var(--sev-low)' } as any}>
          <div className="stat-label">Operational</div>
          <div className="stat-value" style={{ color: 'var(--sev-low)' }}>{available}</div>
          <div className="stat-sub">Active binary installations</div>
        </div>

        <div className="stat-card" style={{ '--card-accent': 'var(--sev-high)' } as any}>
          <div className="stat-label">Fallback Mode</div>
          <div className="stat-value" style={{ color: 'var(--sev-high)' }}>{fallback}</div>
          <div className="stat-sub">Python probe backup active</div>
        </div>

        <div className="stat-card" style={{ '--card-accent': 'var(--sev-critical)' } as any}>
          <div className="stat-label">Unavailable</div>
          <div className="stat-value" style={{ color: 'var(--sev-critical)' }}>{missing}</div>
          <div className="stat-sub">Integrations missing setups</div>
        </div>
      </div>

      {/* Grouped Phase Pipeline Layout */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
        
        {Object.entries(phases).map(([phaseName, phaseTools]) => {
          if (phaseTools.length === 0) return null;
          
          let phaseColor = 'var(--primary-light)';
          if (phaseName === 'Vulnerability Scanning') phaseColor = 'var(--accent-purple)';
          if (phaseName === 'Exploitation') phaseColor = 'var(--sev-high)';

          return (
            <div key={phaseName} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Phase Header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
                <span style={{
                  width: 10, height: 10, borderRadius: '50%', background: phaseColor,
                  boxShadow: `0 0 8px ${phaseColor}`
                }} />
                <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>
                  {phaseName} Stage
                </h2>
                <span style={{
                  fontSize: 11, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)',
                  color: 'var(--text-secondary)', padding: '2px 8px', borderRadius: 20, marginLeft: 8
                }}>
                  {phaseTools.length} {phaseTools.length === 1 ? 'tool' : 'tools'}
                </span>
              </div>

              {/* Grid of Tool Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 20 }}>
                {phaseTools.map((tool: SystemTool) => {
                  const isAvailable = tool.status === 'available';
                  const isFallback = tool.status === 'fallback';
                  
                  let cardBorder = '1px solid var(--border)';
                  let glowEffect = 'none';
                  let statusLabel = 'Missing';
                  let statusClass = 'badge-critical';

                  if (isAvailable) {
                    cardBorder = '1px solid rgba(52, 199, 89, 0.15)';
                    glowEffect = '0 0 15px rgba(52, 199, 89, 0.03)';
                    statusLabel = 'Operational';
                    statusClass = 'badge-low';
                  } else if (isFallback) {
                    cardBorder = '1px solid rgba(255, 149, 0, 0.2)';
                    glowEffect = '0 0 15px rgba(255, 149, 0, 0.03)';
                    statusLabel = 'Fallback Active';
                    statusClass = 'badge-high';
                  }

                  return (
                    <div key={tool.id} className="card" style={{
                      background: 'var(--bg-card)',
                      border: cardBorder,
                      boxShadow: glowEffect,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      gap: 16,
                      padding: 20,
                      borderRadius: 12,
                      transition: 'transform 0.2s, border-color 0.2s'
                    }}>
                      
                      <div>
                        {/* Title & Status */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                          <div>
                            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>{tool.name}</h3>
                            <span className="text-mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                              bin: {tool.binary}
                            </span>
                          </div>
                          <span className={`badge ${statusClass}`} style={{ fontSize: 10 }}>
                            {statusLabel}
                          </span>
                        </div>

                        {/* Description */}
                        <p className="text-secondary" style={{ fontSize: 13, lineHeight: 1.5, marginTop: 10 }}>
                          {tool.description}
                        </p>
                      </div>

                      {/* Details block */}
                      <div style={{
                        background: 'var(--bg-surface)',
                        borderRadius: 6,
                        padding: '10px 12px',
                        border: '1px solid rgba(255, 255, 255, 0.03)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 6
                      }}>
                        {/* Run configuration */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                          <span className="text-muted" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            {tool.execution_mode === 'docker' ? (
                              <Container style={{ width: 12, height: 12, color: 'var(--accent-cyan)' }} />
                            ) : (
                              <Terminal style={{ width: 12, height: 12, color: 'var(--primary-light)' }} />
                            )}
                            Mode:
                          </span>
                          <span style={{ color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'capitalize' }}>
                            {tool.execution_mode}
                          </span>
                        </div>

                        {/* Host path / URL */}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 11 }}>
                          <span className="text-muted">Target Host Resource:</span>
                          <span className="text-mono truncate" style={{
                            color: tool.binary_path ? 'var(--primary-light)' : 'var(--text-muted)',
                            background: 'rgba(0, 0, 0, 0.2)', padding: '2px 4px', borderRadius: 3
                          }}>
                            {tool.binary_path || 'Not registered / not found'}
                          </span>
                        </div>
                      </div>

                      {/* Fallback support note */}
                      {isFallback && (
                        <div style={{
                          display: 'flex', alignItems: 'center', gap: 6, fontSize: 11,
                          color: 'var(--sev-high)', background: 'rgba(255, 149, 0, 0.05)',
                          padding: '6px 10px', borderRadius: 4, border: '1px solid rgba(255, 149, 0, 0.1)'
                        }}>
                          <Info style={{ width: 12, height: 12, flexShrink: 0 }} />
                          <span>Custom Python probe fallback will execute automatically.</span>
                        </div>
                      )}

                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}

      </div>
    </div>
  );
}
