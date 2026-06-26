import React, { useEffect, useState } from 'react';
import { api, SystemTool, SystemToolsResponse } from '../lib/api';
import { Activity, CheckCircle, AlertTriangle, XCircle, Terminal, Container, Shield } from 'lucide-react';

export function ToolStatusPage() {
  const [data, setData] = useState<SystemToolsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
          {/* Header Skeleton */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="skeleton" style={{ width: 250, height: 36 }} />
            <div className="skeleton" style={{ width: 400, height: 20 }} />
          </div>
          {/* Stat Grid Skeleton */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="skeleton" style={{ height: 100, borderRadius: 12 }} />
            ))}
          </div>
          {/* Table Skeleton */}
          <div className="skeleton" style={{ width: '100%', height: 400, borderRadius: 12 }} />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-content animate-fadeIn">
        <div className="card" style={{ border: '1px solid var(--sev-critical)', padding: 32, textAlign: 'center' }}>
          <XCircle className="text-critical" style={{ width: 48, height: 48, marginBottom: 16 }} />
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>System Communication Error</h2>
          <p className="text-secondary" style={{ marginBottom: 24 }}>{error}</p>
          <button className="btn btn-outline" onClick={() => window.location.reload()}>
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  const tools = data?.tools || [];
  const total = tools.length;
  const available = tools.filter(t => t.status === 'available').length;
  const fallback = tools.filter(t => t.status === 'fallback').length;
  const missing = tools.filter(t => t.status === 'missing').length;

  return (
    <div className="page-content animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 12 }}>
            <Activity className="text-accent" style={{ width: 32, height: 32 }} />
            Tool Status
          </h1>
          <p className="text-secondary mt-1">
            Audit availability, binary paths, and running environments for integrated VAPT security scanners.
          </p>
        </div>
      </div>

      {/* Stats Cards Grid */}
      <div className="stat-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card" style={{ '--card-accent': 'var(--primary-light)' } as any}>
          <div className="stat-label">System Mode</div>
          <div className="stat-value" style={{ fontSize: 24, padding: '6px 0', textTransform: 'capitalize' }}>
            {data?.execution_mode || 'Subprocess'}
          </div>
          <div className="stat-sub">Global tool execution mode</div>
        </div>

        <div className="stat-card" style={{ '--card-accent': 'var(--sev-low)' } as any}>
          <div className="stat-label">Available</div>
          <div className="stat-value" style={{ color: 'var(--sev-low)' }}>{available}</div>
          <div className="stat-sub">Fully installed & operational</div>
        </div>

        <div className="stat-card" style={{ '--card-accent': 'var(--sev-high)' } as any}>
          <div className="stat-label">Python Fallback</div>
          <div className="stat-value" style={{ color: 'var(--sev-high)' }}>{fallback}</div>
          <div className="stat-sub">Running via custom script fallback</div>
        </div>

        <div className="stat-card" style={{ '--card-accent': 'var(--sev-critical)' } as any}>
          <div className="stat-label">Missing</div>
          <div className="stat-value" style={{ color: 'var(--sev-critical)' }}>{missing}</div>
          <div className="stat-sub">Requires installation setup</div>
        </div>
      </div>

      {/* Tools Table Container */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Scanning Integrations ({total})</h2>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Status checks are updated on server start or query time
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Tool Integration</th>
                <th>Phase</th>
                <th>Binary Command</th>
                <th>Execution Mode</th>
                <th>Status</th>
                <th>Resolved Path</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool: SystemTool) => {
                let statusBadge = null;
                if (tool.status === 'available') {
                  statusBadge = <span className="badge badge-low">Available</span>;
                } else if (tool.status === 'fallback') {
                  statusBadge = (
                    <span className="badge badge-high" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }} title="Binary is missing. Python network probe will handle the request.">
                      <AlertTriangle style={{ width: 10, height: 10 }} />
                      Fallback Active
                    </span>
                  );
                } else {
                  statusBadge = <span className="badge badge-critical">Missing</span>;
                }

                return (
                  <tr key={tool.id}>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{tool.name}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{tool.description}</span>
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-blue">{tool.phase}</span>
                    </td>
                    <td>
                      <span className="text-mono" style={{ background: 'rgba(255,255,255,0.03)', padding: '2px 6px', borderRadius: 4, fontSize: 12, color: 'var(--text-secondary)' }}>
                        {tool.binary}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {tool.execution_mode === 'docker' ? (
                          <>
                            <Container style={{ width: 14, height: 14, color: 'var(--accent-cyan)' }} />
                            <span>Docker Container</span>
                          </>
                        ) : (
                          <>
                            <Terminal style={{ width: 14, height: 14, color: 'var(--primary-light)' }} />
                            <span>Subprocess (Host)</span>
                          </>
                        )}
                      </div>
                    </td>
                    <td>{statusBadge}</td>
                    <td>
                      <span className="text-mono" style={{ fontSize: 11, color: tool.binary_path ? 'var(--text-secondary)' : 'var(--text-muted)' }} title={tool.binary_path || ''}>
                        {tool.binary_path ? (
                          tool.binary_path.length > 35 ? `...${tool.binary_path.slice(-32)}` : tool.binary_path
                        ) : (
                          'N/A'
                        )}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
