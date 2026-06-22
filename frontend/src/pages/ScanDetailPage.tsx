import React, { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api, Scan, Finding } from '../lib/api';
import { ScanProgress } from '../components/ScanProgress';
import { FindingsTable } from '../components/FindingsTable';
import { LogStream, LogEntry } from '../components/LogStream';
import { ScanWebSocket } from '../lib/websocket';
import { SeverityBadge } from '../components/SeverityBadge';
import { ArrowLeft, Download, Terminal, Shield, Clock } from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'progress' | 'findings' | 'logs'>('progress');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  const loadScan = useCallback(async () => {
    if (!id) return;
    try {
      const s = await api.scans.get(id);
      setScan(s);

      if (s.status === 'completed' || s.finding_count > 0) {
        const f = await api.scans.findings(id, severityFilter || undefined);
        setFindings(f.findings);
      }

      if (s.status === 'completed') {
        try {
          const r = await api.reports.get(id);
          setReport(r);
        } catch (_) {}
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [id, severityFilter]);

  useEffect(() => {
    loadScan();
  }, [loadScan]);

  // WebSocket for live updates
  useEffect(() => {
    if (!id) return;
    if (scan?.status === 'completed' || scan?.status === 'failed' || scan?.status === 'cancelled') return;

    const ws = new ScanWebSocket(id);
    ws.connect();

    ws.on('log', (msg: { level?: string; tool?: string; message: string }) => {
      setLogs(prev => [...prev.slice(-500), {
        time: new Date(),
        level: msg.level || 'info',
        tool: msg.tool || '',
        message: msg.message,
      }]);
    });

    ws.on('progress', () => loadScan());
    ws.on('finding', () => loadScan());

    return () => ws.disconnect();
  }, [id, scan?.status, loadScan]);

  // Polling fallback
  useEffect(() => {
    if (!scan || scan.status === 'completed' || scan.status === 'failed') return;
    const t = setInterval(loadScan, 3000);
    return () => clearInterval(t);
  }, [scan?.status, loadScan]);

  if (loading || !scan) {
    return (
      <div className="page-content">
        <div className="skeleton" style={{ height: 200, borderRadius: 16 }} />
      </div>
    );
  }

  const isRunning = !['completed', 'failed', 'cancelled', 'pending'].includes(scan.status);

  return (
    <div className="page-content animate-fadeIn">
      {/* Back + Header */}
      <div className="flex items-center gap-3 mb-6">
        <Link to="/scans" className="btn btn-outline btn-sm">
          <ArrowLeft size={14} /> Back
        </Link>
        <div style={{ flex: 1 }}>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>{scan.scope?.target}</h1>
          <p className="text-secondary" style={{ fontSize: 12, marginTop: 2 }}>
            {scan.name && scan.name !== `Scan of ${scan.scope?.target}` ? `${scan.name} · ` : ''}
            Created {scan.created_at ? formatDistanceToNow(new Date(scan.created_at), { addSuffix: true }) : '—'}
          </p>
        </div>
        {report?.pdf_path && (
          <a
            href={api.reports.downloadPdfUrl(scan.id)}
            className="btn btn-outline"
            download
          >
            <Download size={14} />
            {report.pdf_path.endsWith('.html') ? 'Download HTML' : 'Download PDF'}
          </a>
        )}
        {report?.json_path && (
          <a
            href={api.reports.downloadJsonUrl(scan.id)}
            className="btn btn-outline btn-sm"
            download
          >
            <Download size={12} />
            JSON
          </a>
        )}
      </div>

      {/* Progress Card */}
      <div className="card mb-6">
        <ScanProgress scan={scan} />
        {scan.error && (
          <div style={{
            marginTop: 16, padding: 12, background: 'var(--sev-critical-bg)',
            border: '1px solid rgba(255,59,48,0.3)', borderRadius: 8,
            color: 'var(--sev-critical)', fontSize: 13,
          }}>
            Error: {scan.error}
          </div>
        )}
      </div>

      {/* Tool Results Timeline */}
      {scan.tool_results && Object.keys(scan.tool_results).length > 0 && (
        <div className="card mb-6">
          <div className="card-header">
            <div className="card-title">Tool Execution</div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {Object.entries(scan.tool_results).map(([tool, result]: [string, any]) => (
              <div key={tool} style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '10px 14px', background: 'var(--bg-elevated)',
                borderRadius: 8, border: '1px solid var(--border)',
              }}>
                <div style={{
                  width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                  background: result.status === 'completed' ? 'var(--accent-green)'
                    : result.status === 'failed' ? 'var(--sev-critical)'
                    : result.status === 'running' ? 'var(--accent-cyan)'
                    : 'var(--text-muted)',
                  boxShadow: result.status === 'running' ? '0 0 8px var(--accent-cyan)' : 'none',
                }} />
                <div style={{ flex: 1, fontFamily: 'JetBrains Mono, monospace', fontSize: 13, fontWeight: 600 }}>
                  {tool}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {result.status}
                  {result.duration_seconds ? ` · ${result.duration_seconds.toFixed(1)}s` : ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Report Summary */}
      {report && (
        <div className="card mb-6" style={{ borderColor: 'var(--border-bright)', background: 'var(--primary-glow)' }}>
          <div className="flex items-center justify-between mb-4">
            <div className="card-title" style={{ color: 'var(--primary-light)' }}>
              AI Report Generated
            </div>
            <span style={{
              fontSize: 24, fontWeight: 900,
              color: report.risk_score >= 60 ? 'var(--sev-critical)' : report.risk_score >= 40 ? 'var(--sev-high)' : 'var(--accent-green)',
            }}>
              Risk: {report.risk_rating} ({report.risk_score}/100)
            </span>
          </div>
          {report.executive_summary && (
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
              {report.executive_summary}
            </p>
          )}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20 }}>
        {(['progress', 'findings', 'logs'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className="btn"
            style={{
              background: activeTab === tab ? 'var(--primary-glow)' : 'transparent',
              border: `1px solid ${activeTab === tab ? 'var(--border-bright)' : 'var(--border)'}`,
              color: activeTab === tab ? 'var(--primary-light)' : 'var(--text-secondary)',
              textTransform: 'capitalize',
            }}
          >
            {tab === 'findings' && <Shield size={14} />}
            {tab === 'logs' && <Terminal size={14} />}
            {tab}
            {tab === 'findings' && findings.length > 0 && (
              <span className="badge badge-critical" style={{ marginLeft: 4 }}>{findings.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'findings' && (
        <div>
          {/* Severity filter */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            {['', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`badge ${sev ? `badge-${sev}` : 'badge-blue'}`}
                style={{
                  cursor: 'pointer', border: 'none',
                  padding: '6px 14px', fontSize: 12,
                  opacity: severityFilter === sev ? 1 : 0.5,
                }}
              >
                {sev || 'All'}
              </button>
            ))}
          </div>
          <FindingsTable findings={findings} />
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Terminal size={14} color="var(--primary-light)" />
            <span style={{ fontWeight: 600, fontSize: 13 }}>Live Scan Logs</span>
            {isRunning && <span className="status-dot" />}
          </div>
          <LogStream logs={logs} />
        </div>
      )}

      {activeTab === 'progress' && (
        <>
          {scan.config?.enable_exploitation && scan.exploitation_stages && (
            <div className="card mb-6 animate-fadeIn">
              <div className="card-header">
                <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Shield size={16} color="var(--primary-light)" />
                  Exploitation Stages
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {Object.entries(scan.exploitation_stages).map(([key, stage]: [string, any]) => {
                  const isActive = stage.status === 'running';
                  const isDone = stage.status === 'completed';
                  const isSkipped = stage.status === 'skipped';
                  const isFailed = stage.status === 'failed';

                  let statusText = 'Pending';
                  let badgeClass = 'badge-blue';
                  if (isActive) { statusText = 'In Progress'; badgeClass = 'badge-info animate-pulse'; }
                  if (isDone) { statusText = 'Completed'; badgeClass = 'badge-success'; }
                  if (isSkipped) { statusText = 'Skipped'; badgeClass = 'badge-gray'; }
                  if (isFailed) { statusText = 'Failed'; badgeClass = 'badge-critical'; }

                  return (
                    <div key={key} style={{
                      display: 'flex', flexDirection: 'column', gap: 6,
                      padding: '12px 16px', background: 'var(--bg-elevated)',
                      borderRadius: 10, border: `1px solid ${isActive ? 'var(--accent-cyan)' : 'var(--border)'}`,
                      boxShadow: isActive ? '0 0 12px rgba(0, 180, 216, 0.15)' : 'none',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ fontWeight: 700, fontSize: 13, color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                          {stage.name}
                        </div>
                        <span className={`badge ${badgeClass}`} style={{ fontSize: 10, padding: '2px 8px' }}>
                          {statusText}
                        </span>
                      </div>
                      {stage.summary && (
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                          {stage.summary}
                        </div>
                      )}
                      {stage.findings_count > 0 && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                          <span className="badge badge-critical" style={{ fontSize: 9, padding: '1px 6px' }}>
                            {stage.findings_count} {stage.findings_count === 1 ? 'Vulnerability' : 'Vulnerabilities'} Identified
                          </span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="card">
            <div className="card-header">
              <div className="card-title">Scan Details</div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
              <Detail label="Scan ID" value={scan.id} mono />
              <Detail label="Target" value={scan.scope?.target} />
              <Detail label="Status" value={scan.status} />
              <Detail label="Progress" value={`${scan.progress_percent}%`} />
              <Detail label="Safe Mode" value={scan.config?.safe_mode ? 'Enabled' : 'Disabled'} />
              <Detail label="Exploitation" value={scan.config?.enable_exploitation ? 'Enabled' : 'Disabled'} />
              <Detail label="Created" value={scan.created_at ? format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm') : '—'} />
              <Detail label="Completed" value={scan.completed_at ? format(new Date(scan.completed_at), 'MMM dd, yyyy HH:mm') : '—'} />
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--text-muted)', marginBottom: 4 }}>
        {label}
      </div>
      <div style={{
        fontSize: 13, color: 'var(--text-secondary)',
        fontFamily: mono ? 'JetBrains Mono, monospace' : 'inherit',
      }}>
        {value || '—'}
      </div>
    </div>
  );
}
