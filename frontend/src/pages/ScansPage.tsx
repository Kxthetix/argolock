import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, Scan, parseUtcDate } from '../lib/api';
import { ScanForm } from '../components/ScanForm';
import { ScanProgress } from '../components/ScanProgress';
import { SeverityBadge } from '../components/SeverityBadge';
import { Plus, Search, X, Zap } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

export function ScansPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [search, setSearch] = useState('');

  const load = async () => {
    try {
      const res = await api.scans.list(0, 50);
      setScans(res.scans);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const filtered = scans.filter(s =>
    s.scope?.target?.toLowerCase().includes(search.toLowerCase()) ||
    s.name?.toLowerCase().includes(search.toLowerCase())
  );

  const handleCreated = (scanId: string) => {
    setShowForm(false);
    navigate(`/scans/${scanId}`);
  };

  return (
    <div className="page-content animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800 }}>Scans</h1>
          <p className="text-secondary mt-1">Manage and monitor your security assessments</p>
        </div>
        <button
          id="new-scan-btn"
          className="btn btn-primary"
          onClick={() => setShowForm(true)}
        >
          <Plus size={16} />
          New Scan
        </button>
      </div>

      {/* Search */}
      <div style={{ position: 'relative', marginBottom: 24 }}>
        <Search size={16} style={{
          position: 'absolute', left: 14, top: '50%',
          transform: 'translateY(-50%)', color: 'var(--text-muted)',
        }} />
        <input
          className="form-input"
          style={{ paddingLeft: 40 }}
          placeholder="Search by target or scan name..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {/* Scan list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {loading
          ? [...Array(3)].map((_, i) => (
            <div key={i} className="card skeleton" style={{ height: 120 }} />
          ))
          : filtered.length === 0
            ? (
              <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-muted)' }}>
                <Zap size={48} color="var(--border)" />
                <div style={{ marginTop: 12, fontSize: 16, fontWeight: 600 }}>No scans yet</div>
                <div style={{ marginTop: 6, fontSize: 13 }}>Click "New Scan" to start your first security assessment</div>
              </div>
            )
            : filtered.map(scan => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                style={{ textDecoration: 'none' }}
              >
                <div className="card" style={{ transition: 'all 0.2s', cursor: 'pointer' }}>
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <div style={{ fontSize: 16, fontWeight: 700 }}>{scan.scope?.target}</div>
                      {scan.name && scan.name !== `Scan of ${scan.scope?.target}` && (
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{scan.name}</div>
                      )}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{ display: 'flex', gap: 8 }}>
                        {scan.critical_count > 0 && <span className="badge badge-critical">{scan.critical_count} Critical</span>}
                        {scan.high_count > 0 && <span className="badge badge-high">{scan.high_count} High</span>}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {scan.created_at ? formatDistanceToNow(parseUtcDate(scan.created_at), { addSuffix: true }) : ''}
                      </div>
                    </div>
                  </div>

                  {['running', 'recon', 'scanning', 'exploiting', 'ai_analysis', 'reporting', 'pending'].includes(scan.status) && (
                    <ScanProgress scan={scan} />
                  )}

                  {scan.status === 'completed' && (
                    <div style={{ fontSize: 12, color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      ✓ Completed — {scan.finding_count} findings identified
                    </div>
                  )}

                  {scan.status === 'failed' && (
                    <div style={{ fontSize: 12, color: 'var(--sev-critical)' }}>
                      ✗ Failed: {scan.error || 'Unknown error'}
                    </div>
                  )}
                </div>
              </Link>
            ))
        }
      </div>

      {/* New Scan Modal */}
      {showForm && (
        <div className="modal-overlay" onClick={e => { if (e.target === e.currentTarget) setShowForm(false); }}>
          <div className="modal">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 style={{ fontSize: 20, fontWeight: 700 }}>Launch New Scan</h2>
                <p className="text-secondary mt-1" style={{ fontSize: 13 }}>Configure and start a VAPT assessment</p>
              </div>
              <button
                onClick={() => setShowForm(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>
            <ScanForm onCreated={handleCreated} />
          </div>
        </div>
      )}
    </div>
  );
}
