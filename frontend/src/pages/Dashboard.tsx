import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api, Scan } from '../lib/api';
import { ScanProgress } from '../components/ScanProgress';
import { SeverityBadge } from '../components/SeverityBadge';
import {
  Activity, Shield, AlertTriangle, TrendingUp,
  Plus, ArrowRight, Clock, CheckCircle, XCircle, Scan as ScanIcon
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';
import { formatDistanceToNow } from 'date-fns';

const SEVERITY_COLORS = {
  critical: '#ff3b30',
  high: '#ff9500',
  medium: '#ffcc00',
  low: '#34c759',
  info: '#007aff',
};

export function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const loadScans = async () => {
    try {
      const res = await api.scans.list(0, 50);
      setScans(res.scans);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
    const timer = setInterval(loadScans, 5000);
    return () => clearInterval(timer);
  }, []);

  // Aggregate stats
  const totalFindings = scans.reduce((s, sc) => s + (sc.finding_count || 0), 0);
  const criticalTotal = scans.reduce((s, sc) => s + (sc.critical_count || 0), 0);
  const highTotal = scans.reduce((s, sc) => s + (sc.high_count || 0), 0);
  const activeScans = scans.filter(s => ['running', 'recon', 'scanning', 'exploiting', 'ai_analysis', 'reporting'].includes(s.status)).length;
  const completedScans = scans.filter(s => s.status === 'completed').length;

  // Chart data
  const severityData = [
    { name: 'Critical', value: criticalTotal, color: SEVERITY_COLORS.critical },
    { name: 'High', value: highTotal, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: scans.reduce((s, sc) => s + (sc.medium_count || 0), 0), color: SEVERITY_COLORS.medium },
    { name: 'Low', value: scans.reduce((s, sc) => s + (sc.low_count || 0), 0), color: SEVERITY_COLORS.low },
  ].filter(d => d.value > 0);

  const recentScans = scans.slice(0, 10);

  return (
    <div className="page-content animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800 }}>Security Dashboard</h1>
          <p className="text-secondary mt-1">ArgoLock AI-powered vulnerability assessment overview</p>
        </div>
        <Link to="/scans" className="btn btn-primary">
          <Plus size={16} />
          New Scan
        </Link>
      </div>

      {/* Stat Cards */}
      <div className="stat-grid">
        <div className="stat-card" style={{ '--card-accent': 'var(--primary)' } as any}>
          <ScanIcon size={20} className="text-muted" style={{ position: 'absolute', top: 24, right: 24, opacity: 0.4 }} />
          <div className="stat-label">Total Scans</div>
          <div className="stat-value">{scans.length}</div>
          <div className="stat-sub">{completedScans} completed</div>
        </div>
        <div className="stat-card" style={{ '--card-accent': '#00d4ff' } as any}>
          <Activity size={20} className="text-muted" style={{ position: 'absolute', top: 24, right: 24, opacity: 0.5 }} />
          <div className="stat-label">Active Scans</div>
          <div className="stat-value">{activeScans}</div>
          <div className="stat-sub">running now</div>
        </div>
        <div className="stat-card" style={{ '--card-accent': 'var(--sev-critical)' } as any}>
          <AlertTriangle size={20} className="text-muted" style={{ position: 'absolute', top: 24, right: 24, opacity: 0.4 }} />
          <div className="stat-label">Critical Findings</div>
          <div className="stat-value">{criticalTotal}</div>
          <div className="stat-sub">require immediate action</div>
        </div>
        <div className="stat-card" style={{ '--card-accent': 'var(--sev-high)' } as any}>
          <Shield size={20} className="text-muted" style={{ position: 'absolute', top: 24, right: 24, opacity: 0.4 }} />
          <div className="stat-label">High Severity</div>
          <div className="stat-value">{highTotal}</div>
          <div className="stat-sub">across all scans</div>
        </div>
        <div className="stat-card" style={{ '--card-accent': 'var(--accent-green)' } as any}>
          <TrendingUp size={20} className="text-muted" style={{ position: 'absolute', top: 24, right: 24, opacity: 0.4 }} />
          <div className="stat-label">Total Findings</div>
          <div className="stat-value">{totalFindings}</div>
          <div className="stat-sub">AI-analyzed</div>
        </div>
      </div>

      {/* Charts + Active Scans */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 32 }}>

        {/* Severity Distribution */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Severity Distribution</div>
          </div>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: 8,
                    color: 'var(--text-primary)',
                  }}
                />
                <Legend formatter={(value) => (
                  <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{value}</span>
                )} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
              No findings yet — run a scan
            </div>
          )}
        </div>

        {/* Active Scans */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Active Scans</div>
            <Activity size={16} color="var(--primary-light)" />
          </div>
          {activeScans === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, textAlign: 'center', padding: '40px 0' }}>
              No active scans
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {scans
                .filter(s => ['running', 'recon', 'scanning', 'exploiting', 'ai_analysis', 'reporting'].includes(s.status))
                .slice(0, 3)
                .map(scan => (
                  <Link
                    key={scan.id}
                    to={`/scans/${scan.id}`}
                    style={{ textDecoration: 'none' }}
                  >
                    <div style={{
                      padding: '12px 16px', background: 'var(--bg-elevated)',
                      borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                      transition: 'border-color 0.2s',
                    }}>
                      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8, color: 'var(--text-primary)' }}>
                        {scan.scope?.target}
                      </div>
                      <ScanProgress scan={scan} />
                    </div>
                  </Link>
                ))
              }
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Recent Scans</div>
          <Link to="/scans" className="btn btn-outline btn-sm">
            View All <ArrowRight size={12} />
          </Link>
        </div>
        <div className="table-container" style={{ border: 'none' }}>
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Critical</th>
                <th>High</th>
                <th>Started</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? [...Array(5)].map((_, i) => (
                  <tr key={i}>
                    {[...Array(7)].map((_, j) => (
                      <td key={j}><div className="skeleton" style={{ height: 16, borderRadius: 4 }} /></td>
                    ))}
                  </tr>
                ))
                : recentScans.map(scan => (
                  <tr key={scan.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{scan.scope?.target}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {scan.name !== `Scan of ${scan.scope?.target}` ? scan.name : ''}
                      </div>
                    </td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td style={{ fontWeight: 700 }}>{scan.finding_count}</td>
                    <td style={{ color: 'var(--sev-critical)', fontWeight: 700 }}>{scan.critical_count}</td>
                    <td style={{ color: 'var(--sev-high)', fontWeight: 700 }}>{scan.high_count}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                      {scan.created_at ? formatDistanceToNow(new Date(scan.created_at), { addSuffix: true }) : '—'}
                    </td>
                    <td>
                      <Link to={`/scans/${scan.id}`} className="btn btn-outline btn-sm">
                        View
                      </Link>
                    </td>
                  </tr>
                ))
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const configs: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    pending: { label: 'Queued', color: 'var(--text-muted)', icon: <Clock size={10} /> },
    running: { label: 'Running', color: 'var(--accent-cyan)', icon: <Activity size={10} /> },
    recon: { label: 'Recon', color: 'var(--accent-cyan)', icon: <Activity size={10} /> },
    scanning: { label: 'Scanning', color: 'var(--primary-light)', icon: <Activity size={10} /> },
    exploiting: { label: 'Exploiting', color: 'var(--sev-high)', icon: <Activity size={10} /> },
    ai_analysis: { label: 'AI Analysis', color: '#a855f7', icon: <Activity size={10} /> },
    reporting: { label: 'Reporting', color: 'var(--accent-green)', icon: <Activity size={10} /> },
    completed: { label: 'Completed', color: 'var(--accent-green)', icon: <CheckCircle size={10} /> },
    failed: { label: 'Failed', color: 'var(--sev-critical)', icon: <XCircle size={10} /> },
    cancelled: { label: 'Cancelled', color: 'var(--text-muted)', icon: <XCircle size={10} /> },
  };

  const cfg = configs[status] || { label: status, color: 'var(--text-muted)', icon: null };

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      fontSize: 11, fontWeight: 600, color: cfg.color,
      padding: '3px 10px', borderRadius: 20,
      background: `${cfg.color}18`, border: `1px solid ${cfg.color}40`,
    }}>
      {cfg.icon}
      {cfg.label}
    </span>
  );
}
