import React, { useState, useEffect } from 'react';
import { api, Finding } from '../lib/api';
import { FindingsTable } from '../components/FindingsTable';
import { Shield } from 'lucide-react';

export function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const res = await api.findings.list({ severity: severityFilter || undefined, limit: 200 });
        setFindings(res.findings);
      } catch (e) { console.error(e); }
      finally { setLoading(false); }
    };
    load();
  }, [severityFilter]);

  return (
    <div className="page-content animate-fadeIn">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800 }}>All Findings</h1>
          <p className="text-secondary mt-1">
            {findings.length} findings across all scans
          </p>
        </div>
      </div>

      {/* Filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        {['', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={`badge ${sev ? `badge-${sev}` : 'badge-blue'}`}
            style={{
              cursor: 'pointer', border: 'none',
              padding: '6px 16px', fontSize: 12,
              opacity: severityFilter === sev ? 1 : 0.5,
            }}
          >
            {sev || 'All Severities'}
          </button>
        ))}
      </div>

      <FindingsTable findings={findings} loading={loading} />
    </div>
  );
}
