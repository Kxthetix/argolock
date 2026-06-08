import React, { useEffect, useRef } from 'react';
import { format } from 'date-fns';

export interface LogEntry {
  time: Date;
  level: string;
  tool: string;
  message: string;
}

interface Props {
  logs: LogEntry[];
}

export function LogStream({ logs }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="log-stream">
      {logs.length === 0 && (
        <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>
          Waiting for scan to start...
        </div>
      )}
      {logs.map((log, i) => (
        <div key={i} className={`log-line log-${log.level}`}>
          <span className="log-time">{format(log.time, 'HH:mm:ss')}</span>
          {log.tool && <span className="log-tool">[{log.tool}]</span>}
          <span className="log-message">{log.message}</span>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  );
}
