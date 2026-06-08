import React from 'react';
import { Finding } from '../lib/api';
import { SeverityBadge } from './SeverityBadge';
import { ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';

interface Props {
  findings: Finding[];
  loading?: boolean;
}

export function FindingsTable({ findings, loading }: Props) {
  const [expanded, setExpanded] = React.useState<string | null>(null);

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[...Array(5)].map((_, i) => (
          <div key={i} className="skeleton" style={{ height: 56, borderRadius: 8 }} />
        ))}
      </div>
    );
  }

  if (!findings.length) {
    return (
      <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
        <div style={{ fontSize: 48, marginBottom: 12 }}>🔍</div>
        <div>No findings yet</div>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th style={{ width: 32 }} />
            <th>Title</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>OWASP</th>
            <th>Endpoint</th>
            <th>Tool</th>
          </tr>
        </thead>
        <tbody>
          {findings.map(finding => (
            <React.Fragment key={finding.id}>
              <tr
                style={{ cursor: 'pointer' }}
                onClick={() => setExpanded(expanded === finding.id ? null : finding.id)}
              >
                <td>
                  {expanded === finding.id
                    ? <ChevronDown size={14} color="var(--text-muted)" />
                    : <ChevronRight size={14} color="var(--text-muted)" />
                  }
                </td>
                <td>
                  <div style={{ fontWeight: 500, fontSize: 13 }}>{finding.title}</div>
                </td>
                <td><SeverityBadge severity={finding.severity} /></td>
                <td>
                  <span
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontWeight: 700,
                      color: getSeverityColor(finding.severity),
                    }}
                  >
                    {finding.cvss_score?.toFixed(1) || '—'}
                  </span>
                </td>
                <td>
                  <span
                    style={{
                      fontSize: 11,
                      color: 'var(--text-muted)',
                      background: 'var(--bg-elevated)',
                      padding: '2px 8px',
                      borderRadius: 4,
                    }}
                  >
                    {finding.owasp_category?.split(' ')[0] || '—'}
                  </span>
                </td>
                <td>
                  <span
                    className="truncate text-mono"
                    style={{ fontSize: 12, color: 'var(--accent-cyan)', maxWidth: 200, display: 'block' }}
                  >
                    {finding.affected_endpoint}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    {finding.tool_source}
                  </span>
                </td>
              </tr>

              {expanded === finding.id && (
                <tr>
                  <td colSpan={7} style={{ padding: 0, background: 'var(--bg-elevated)' }}>
                    <FindingDetail finding={finding} />
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div style={{ padding: '20px 24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
      {/* Left Column */}
      <div>
        <Section title="Description">
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{finding.description}</p>
        </Section>

        {finding.poc?.payload && (
          <Section title="Proof of Concept">
            <div className="code-block">{finding.poc.payload}</div>
          </Section>
        )}

        {finding.poc?.reproduction_steps && finding.poc.reproduction_steps.length > 0 && (
          <Section title="Reproduction Steps">
            <ol style={{ paddingLeft: 20, color: 'var(--text-secondary)', fontSize: 13 }}>
              {finding.poc.reproduction_steps.map((step: string, i: number) => (
                <li key={i} style={{ marginBottom: 4 }}>{step}</li>
              ))}
            </ol>
          </Section>
        )}

        {finding.cve_ids && finding.cve_ids.length > 0 && (
          <Section title="CVE References">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {finding.cve_ids.map((cve: string) => (
                <a
                  key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="badge badge-blue"
                  style={{ textDecoration: 'none' }}
                >
                  {cve} <ExternalLink size={10} />
                </a>
              ))}
            </div>
          </Section>
        )}
      </div>

      {/* Right Column — Remediation */}
      {finding.remediation && (
        <div>
          <Section title="Root Cause">
            <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
              {finding.remediation.root_cause || '—'}
            </p>
          </Section>

          {finding.remediation.fix_steps && finding.remediation.fix_steps.length > 0 && (
            <Section title="Remediation Steps">
              <ol style={{ paddingLeft: 20, color: 'var(--text-secondary)', fontSize: 13 }}>
                {finding.remediation.fix_steps.map((step: string, i: number) => (
                  <li key={i} style={{ marginBottom: 6 }}>{step}</li>
                ))}
              </ol>
            </Section>
          )}

          {finding.remediation.secure_code_example && (
            <Section title="Secure Code Example">
              <div className="code-block" style={{ fontSize: 11 }}>
                {finding.remediation.secure_code_example}
              </div>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{
        fontSize: 10,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: 1,
        color: 'var(--primary-light)',
        marginBottom: 8,
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function getSeverityColor(severity: string) {
  const colors: Record<string, string> = {
    critical: 'var(--sev-critical)',
    high: 'var(--sev-high)',
    medium: 'var(--sev-medium)',
    low: 'var(--sev-low)',
    info: 'var(--sev-info)',
  };
  return colors[severity?.toLowerCase()] || 'var(--text-muted)';
}
