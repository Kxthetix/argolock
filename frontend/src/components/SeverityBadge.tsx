import React from 'react';

interface Props {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
}

const CONFIG: Record<string, { label: string; cls: string; dot: string }> = {
  critical: { label: 'Critical', cls: 'badge-critical', dot: 'var(--sev-critical)' },
  high:     { label: 'High',     cls: 'badge-high',     dot: 'var(--sev-high)' },
  medium:   { label: 'Medium',   cls: 'badge-medium',   dot: 'var(--sev-medium)' },
  low:      { label: 'Low',      cls: 'badge-low',      dot: 'var(--sev-low)' },
  info:     { label: 'Info',     cls: 'badge-info',     dot: 'var(--sev-info)' },
};

export function SeverityBadge({ severity }: Props) {
  const key = severity?.toLowerCase() || 'info';
  const config = CONFIG[key] || CONFIG.info;

  return (
    <span className={`badge ${config.cls}`}>
      <span
        style={{
          width: 5, height: 5, borderRadius: '50%',
          background: config.dot, display: 'inline-block', flexShrink: 0,
        }}
      />
      {config.label}
    </span>
  );
}
