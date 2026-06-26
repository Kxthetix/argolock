import React, { useEffect, useState } from 'react';
import { api, SystemAgent, SystemAgentsResponse } from '../lib/api';
import { Cpu, Brain, CheckCircle, XCircle, Key, FileCode } from 'lucide-react';

export function AgentsPage() {
  const [data, setData] = useState<SystemAgentsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchAgents = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.system.agents();
        setData(res);
      } catch (err: any) {
        console.error('Failed to fetch agents:', err);
        setError(err.message || 'Failed to fetch AI Agent configuration status.');
      } finally {
        setLoading(false);
      }
    };
    fetchAgents();
  }, []);

  if (loading) {
    return (
      <div className="page-content animate-fadeIn">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          {/* Title Skeleton */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="skeleton" style={{ width: 250, height: 36 }} />
            <div className="skeleton" style={{ width: 400, height: 20 }} />
          </div>
          {/* Summary Card Skeleton */}
          <div className="skeleton" style={{ width: '100%', height: 160, borderRadius: 12 }} />
          {/* Grid Skeleton */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 20 }}>
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="skeleton" style={{ height: 220, borderRadius: 12 }} />
            ))}
          </div>
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

  const activeProviderName = data?.active_provider
    ? data.active_provider.charAt(0).toUpperCase() + data.active_provider.slice(1)
    : 'None';

  return (
    <div className="page-content animate-fadeIn">
      {/* Page Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 12 }}>
            <Brain className="text-accent" style={{ width: 32, height: 32 }} />
            AI Agents
          </h1>
          <p className="text-secondary mt-1">
            Monitor autonomous AI agents, prompt configurations, and LLM orchestration settings.
          </p>
        </div>
      </div>

      {/* Provider Status Summary Card */}
      <div className="card mb-6" style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 32, justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
              Active AI Provider
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--primary-light)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
              {activeProviderName}
              <span className={`badge ${data?.provider_configured ? 'badge-low' : 'badge-critical'}`} style={{ fontSize: 10 }}>
                {data?.provider_configured ? 'Operational' : 'Key Missing'}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
              Active Model: <span className="text-mono" style={{ color: 'var(--accent-cyan)' }}>{data?.active_model}</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            {/* OpenAI */}
            <div style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              padding: '12px 16px',
              display: 'flex',
              alignItems: 'center',
              gap: 12
            }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600 }}>OpenAI (GPT-4o)</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {data?.openai_configured ? 'API key configured' : 'API key missing'}
                </div>
              </div>
              {data?.openai_configured ? (
                <CheckCircle className="text-low" style={{ width: 18, height: 18 }} />
              ) : (
                <XCircle className="text-muted" style={{ width: 18, height: 18 }} />
              )}
            </div>

            {/* Anthropic */}
            <div style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              padding: '12px 16px',
              display: 'flex',
              alignItems: 'center',
              gap: 12
            }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600 }}>Anthropic (Claude 3.5)</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {data?.claude_configured ? 'API key configured' : 'API key missing'}
                </div>
              </div>
              {data?.claude_configured ? (
                <CheckCircle className="text-low" style={{ width: 18, height: 18 }} />
              ) : (
                <XCircle className="text-muted" style={{ width: 18, height: 18 }} />
              )}
            </div>

            {/* Ollama */}
            <div style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              padding: '12px 16px',
              display: 'flex',
              alignItems: 'center',
              gap: 12
            }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600 }}>Ollama (Local)</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Local engine enabled
                </div>
              </div>
              <CheckCircle className="text-low" style={{ width: 18, height: 18 }} />
            </div>
          </div>
        </div>
      </div>

      {/* Agents Grid */}
      <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Orchestrated Agents ({data?.agents.length || 0})</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 20 }}>
        {data?.agents.map((agent: SystemAgent) => (
          <div key={agent.id} className="card" style={{
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            gap: 16,
            position: 'relative',
            overflow: 'hidden'
          }}>
            {/* Background glow for active agents */}
            {agent.status === 'active' && (
              <div style={{
                position: 'absolute',
                top: 0,
                right: 0,
                width: 100,
                height: 100,
                background: 'radial-gradient(circle, rgba(99, 102, 241, 0.08) 0%, transparent 70%)',
                pointerEvents: 'none'
              }} />
            )}

            <div>
              {/* Card Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <h3 style={{ fontSize: 16, fontWeight: 700 }}>{agent.name}</h3>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                    {agent.role}
                  </span>
                </div>
                <Cpu className={agent.status === 'active' ? 'text-accent' : 'text-muted'} style={{ width: 20, height: 20 }} />
              </div>

              {/* Description */}
              <p className="text-secondary" style={{ fontSize: 13, lineHeight: 1.5, marginBottom: 16 }}>
                {agent.description}
              </p>
            </div>

            {/* Footer / Specs */}
            <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {/* Prompt configuration file */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                <FileCode style={{ width: 14, height: 14 }} />
                <span>System template: <span className="text-mono" style={{ color: 'var(--text-secondary)' }}>{agent.prompt_file}</span></span>
              </div>

              <div style={{ display: 'flex', justifySelf: 'flex-end', justifyContent: 'space-between', alignItems: 'center', marginTop: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)' }}>
                  <Key style={{ width: 14, height: 14 }} />
                  <span>Configured model: <span className="text-mono" style={{ color: 'var(--text-secondary)' }}>{data.active_model}</span></span>
                </div>
                <span className={`badge ${agent.status === 'active' ? 'badge-low' : 'badge-critical'}`}>
                  {agent.status}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
