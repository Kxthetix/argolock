import React from 'react';
import { Scan } from '../lib/api';

interface Props {
  scan: Scan;
  onFilterSelect?: (severity: string) => void;
}

const PHASES = [
  { key: 'pending', label: 'Queued' },
  { key: 'recon', label: 'Recon' },
  { key: 'scanning', label: 'Scanning' },
  { key: 'exploiting', label: 'Exploit' },
  { key: 'ai_analysis', label: 'AI Analysis' },
  { key: 'reporting', label: 'Report' },
  { key: 'completed', label: 'Complete' },
];

const PHASE_ORDER = PHASES.map(p => p.key);

export function ScanProgress({ scan, onFilterSelect }: Props) {
  const currentIndex = PHASE_ORDER.indexOf(scan.status);
  const infoCount = scan.info_count ?? Math.max(0, scan.finding_count - (scan.critical_count + scan.high_count + scan.medium_count + scan.low_count));

  return (
    <div>
      {/* Progress Bar */}
      <div style={{ marginBottom: 16 }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between',
          fontSize: 12, marginBottom: 8,
        }}>
          <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>
            {scan.current_phase || getStatusLabel(scan.status)}
          </span>
          <span style={{ color: 'var(--primary-light)', fontWeight: 700 }}>
            {scan.progress_percent}%
          </span>
        </div>
        <div className="progress-track">
          <div
            className="progress-fill"
            style={{ width: `${scan.progress_percent}%` }}
          />
        </div>
      </div>

      {/* Phase Pipeline */}
      <div className="pipeline" style={{ gap: 4 }}>
        {PHASES.map((phase, i) => {
          const phaseIndex = PHASE_ORDER.indexOf(phase.key);
          const isDone = phaseIndex < currentIndex || scan.status === 'completed';
          const isActive = phase.key === scan.status;
          const isFailed = scan.status === 'failed' && phaseIndex <= currentIndex;

          return (
            <React.Fragment key={phase.key}>
              <div
                className={`pipeline-step ${isActive ? 'active' : ''} ${isDone ? 'done' : ''} ${isFailed ? 'failed' : ''}`}
                style={{ fontSize: 11 }}
              >
                {isDone && !isFailed && <span>✓</span>}
                {isFailed && <span>✗</span>}
                {isActive && (
                  <svg className="animate-spin" width={10} height={10} viewBox="0 0 24 24" fill="none">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" strokeOpacity="0.3" />
                    <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
                  </svg>
                )}
                {phase.label}
              </div>
              {i < PHASES.length - 1 && (
                <div className="pipeline-arrow">›</div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Counts */}
      {scan.finding_count > 0 && (
        <div style={{
          display: 'flex', gap: 16, marginTop: 16,
          padding: '12px 16px', background: 'var(--bg-elevated)',
          borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
          flexWrap: 'wrap',
        }}>
          <FindCount label="Total" value={scan.finding_count} color="var(--text-primary)" onClick={onFilterSelect ? () => onFilterSelect('') : undefined} />
          <FindCount label="Critical" value={scan.critical_count} color="var(--sev-critical)" onClick={onFilterSelect ? () => onFilterSelect('critical') : undefined} />
          <FindCount label="High" value={scan.high_count} color="var(--sev-high)" onClick={onFilterSelect ? () => onFilterSelect('high') : undefined} />
          <FindCount label="Medium" value={scan.medium_count} color="var(--sev-medium)" onClick={onFilterSelect ? () => onFilterSelect('medium') : undefined} />
          <FindCount label="Low" value={scan.low_count} color="var(--sev-low)" onClick={onFilterSelect ? () => onFilterSelect('low') : undefined} />
          <FindCount label="Info" value={infoCount} color="var(--sev-info)" onClick={onFilterSelect ? () => onFilterSelect('info') : undefined} />
        </div>
      )}
    </div>
  );
}

function FindCount({ label, value, color, onClick }: { label: string; value: number; color: string; onClick?: () => void }) {
  return (
    <div 
      onClick={onClick}
      style={{ 
        textAlign: 'center', 
        minWidth: 48,
        cursor: onClick ? 'pointer' : 'default',
        padding: '2px 6px',
        borderRadius: 6,
        transition: 'background 0.15s ease, transform 0.15s ease',
      }}
      title={onClick ? `View ${label} findings` : undefined}
      className={onClick ? 'hover:bg-white/5' : ''}
    >
      <div style={{ fontSize: 18, fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
        {label}
      </div>
    </div>
  );
}

function getStatusLabel(status: string) {
  const labels: Record<string, string> = {
    pending: 'Queued',
    running: 'Running',
    recon: 'Reconnaissance',
    scanning: 'Vulnerability Scanning',
    exploiting: 'Exploitation',
    ai_analysis: 'AI Analysis',
    reporting: 'Report Generation',
    completed: 'Complete',
    failed: 'Failed',
    cancelled: 'Cancelled',
  };
  return labels[status] || status;
}
