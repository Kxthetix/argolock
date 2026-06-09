import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { FileText, Download, ExternalLink, AlertTriangle } from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';

export function ReportsPage() {
  const [reports, setReports] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.scans.list(0, 50);
        const completedScans = res.scans.filter((s: any) => s.status === 'completed');
        setScans(completedScans);

        // Load reports for completed scans
        const reportPromises = completedScans.map((s: any) =>
          api.reports.get(s.id).catch(() => null)
        );
        const results = await Promise.all(reportPromises);
        setReports(results.filter(Boolean));
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const riskColor = (rating: string) => {
    const r = (rating || '').toLowerCase();
    if (r.includes('critical')) return 'var(--sev-critical)';
    if (r.includes('high')) return 'var(--sev-high)';
    if (r.includes('elevated')) return 'var(--sev-high)';
    if (r.includes('medium') || r.includes('moderate')) return 'var(--sev-medium)';
    if (r.includes('low')) return 'var(--sev-low)';
    return 'var(--text-muted)';
  };

  return (
    <div className="page-content animate-fadeIn">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800 }}>Reports</h1>
          <p className="text-secondary mt-1">Download professional security assessment reports</p>
        </div>
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {[1, 2, 3].map(i => (
            <div key={i} className="card skeleton" style={{ height: 120 }} />
          ))}
        </div>
      ) : reports.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '80px 20px', color: 'var(--text-muted)' }}>
          <FileText size={64} color="var(--border)" />
          <div style={{ marginTop: 16, fontSize: 18, fontWeight: 600 }}>No reports yet</div>
          <div style={{ marginTop: 8, fontSize: 14 }}>
            Complete a scan to generate your first security report
          </div>
          <Link to="/scans" className="btn btn-primary" style={{ marginTop: 24, display: 'inline-flex' }}>
            Start a Scan
          </Link>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {reports.map(report => {
            const scan = scans.find(s => s.id === report.scan_id);
            return (
              <div key={report.id} className="card">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <div style={{ fontSize: 17, fontWeight: 700 }}>
                      {scan?.scope?.target || report.scan_id}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                      Generated {report.generated_at
                        ? formatDistanceToNow(new Date(report.generated_at), { addSuffix: true })
                        : '—'}
                    </div>
                  </div>

                  <div style={{ textAlign: 'right' }}>
                    <div style={{
                      fontSize: 28, fontWeight: 900,
                      color: riskColor(report.risk_rating),
                    }}>
                      {report.risk_score}/100
                    </div>
                    <div style={{ fontSize: 11, color: riskColor(report.risk_rating), fontWeight: 700 }}>
                      {report.risk_rating} Risk
                    </div>
                  </div>
                </div>

                {report.executive_summary && (
                  <p style={{
                    fontSize: 13, color: 'var(--text-secondary)',
                    lineHeight: 1.7, marginBottom: 16,
                    display: '-webkit-box',
                    WebkitLineClamp: 3,
                    WebkitBoxOrient: 'vertical' as any,
                    overflow: 'hidden',
                  }}>
                    {report.executive_summary}
                  </p>
                )}

                <div className="divider" style={{ margin: '12px 0' }} />

                <div className="flex items-center justify-between">
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {report.total_findings} findings · {report.format?.toUpperCase()} format
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    <Link to={`/scans/${report.scan_id}`} className="btn btn-outline btn-sm">
                      <ExternalLink size={12} />
                      View Scan
                    </Link>
                    {report.pdf_path && (
                      <a
                        href={api.reports.downloadPdfUrl(report.scan_id)}
                        className="btn btn-primary btn-sm"
                        download
                      >
                        <Download size={12} />
                        PDF Report
                      </a>
                    )}
                    {report.json_path && (
                      <a
                        href={api.reports.downloadJsonUrl(report.scan_id)}
                        className="btn btn-outline btn-sm"
                        download
                      >
                        <Download size={12} />
                        JSON
                      </a>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
