import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, SystemAgent, SystemAgentsResponse } from '../lib/api';
import { Cpu, Brain, CheckCircle, XCircle, Key, FileCode, Sliders, ShieldAlert } from 'lucide-react';

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
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="skeleton" style={{ width: 250, height: 36 }} />
            <div className="skeleton" style={{ width: 400, height: 20 }} />
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24 }}>
            <div className="skeleton" style={{ flex: '1 1 320px', height: 350, borderRadius: 16 }} />
            <div className="skeleton" style={{ flex: '2 1 600px', height: 400, borderRadius: 16 }} />
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-content animate-fadeIn">
        <div className="card" style={{ border: '1px solid var(--sev-critical)', padding: 40, textAlign: 'center', background: 'rgba(255,59,48,0.03)' }}>
          <ShieldAlert className="text-critical" style={{ width: 64, height: 64, marginBottom: 20, filter: 'drop-shadow(0 0 10px rgba(255,59,48,0.2))' }} />
          <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 8 }}>
            System Communication Error
          </h2>
          <p className="text-secondary" style={{ marginBottom: 28, maxWidth: 500, margin: '0 auto 24px' }}>
            {error}
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
            <button className="btn btn-outline" onClick={() => window.location.reload()}>
              Retry Connection
            </button>
            <Link to="/dashboard" className="btn btn-primary" style={{ textDecoration: 'none' }}>
              Dashboard
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const activeProviderName = data?.active_provider
    ? data.active_provider.charAt(0).toUpperCase() + data.active_provider.slice(1)
    : 'None';

  return (
    <div className="page-content animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 style={{ fontSize: 32, fontWeight: 900, display: 'flex', alignItems: 'center', gap: 12, letterSpacing: '-0.5px' }}>
            <Brain className="text-accent" style={{ width: 36, height: 36, filter: 'drop-shadow(0 0 10px rgba(0,212,255,0.3))' }} />
            AI Agents
          </h1>
          <p className="text-secondary mt-2" style={{ fontSize: 15 }}>
            Monitor and configure specialized LLM agents driving autonomous scans, risk analysis, and remediation generation.
          </p>
        </div>
      </div>

      {/* Split Page Layout */}
      <div style={{ display: 'flex', flexDirection: 'row', flexWrap: 'wrap', gap: 24 }}>
        
        {/* Left Side Panel: Provider Configuration details */}
        <div style={{ flex: '1 1 320px', display: 'flex', flexDirection: 'column', gap: 24 }}>
          
          <div className="card" style={{
            background: 'linear-gradient(135deg, var(--bg-surface) 0%, rgba(99,102,241,0.05) 100%)',
            border: '1px solid var(--border-bright)',
            position: 'relative'
          }}>
            <div style={{
              position: 'absolute', top: 12, right: 12, width: 8, height: 8, borderRadius: '50%',
              background: data?.provider_configured ? 'var(--accent-green)' : 'var(--sev-critical)',
              boxShadow: data?.provider_configured ? '0 0 10px var(--accent-green)' : '0 0 10px var(--sev-critical)'
            }} />
            
            <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 16 }}>Gateway Config</h2>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Active Provider</div>
                <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', marginTop: 2 }}>
                  {activeProviderName}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Target LLM Model</div>
                <div className="text-mono" style={{ fontSize: 13, color: 'var(--accent-cyan)', marginTop: 2, background: 'rgba(0,212,255,0.05)', padding: '4px 8px', borderRadius: 4, display: 'inline-block' }}>
                  {data?.active_model}
                </div>
              </div>

              <div className="divider" style={{ margin: '8px 0' }} />

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)' }}>Connection Checklist</div>
                
                {/* OpenAI setup */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 13 }}>
                  <span className="text-secondary">OpenAI API Connection</span>
                  {data?.openai_configured ? (
                    <span style={{ color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 6, fontWeight: 500 }}>
                      <CheckCircle style={{ width: 14, height: 14 }} /> Connected
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <XCircle style={{ width: 14, height: 14 }} /> Key Missing
                    </span>
                  )}
                </div>

                {/* Anthropic setup */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 13 }}>
                  <span className="text-secondary">Anthropic API Connection</span>
                  {data?.claude_configured ? (
                    <span style={{ color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 6, fontWeight: 500 }}>
                      <CheckCircle style={{ width: 14, height: 14 }} /> Connected
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <XCircle style={{ width: 14, height: 14 }} /> Key Missing
                    </span>
                  )}
                </div>

                {/* Ollama Setup */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 13 }}>
                  <span className="text-secondary">Ollama Engine (Local)</span>
                  <span style={{ color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 6, fontWeight: 500 }}>
                    <CheckCircle style={{ width: 14, height: 14 }} /> Available
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Prompt Engine Status Card */}
          <div className="card" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Sliders style={{ width: 16, height: 16, color: 'var(--primary-light)' }} />
              Agent Hyperparameters
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">Orchestrator Mode</span>
                <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>Sequential Pipeline</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">Agent Temperature</span>
                <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>0.3 (Strict Analysis)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">Max Response Tokens</span>
                <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>4,096 tokens</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="text-muted">System Context Isolation</span>
                <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>Enabled</span>
              </div>
            </div>
          </div>

        </div>

        {/* Right Side Panel: Agent list vertical stack (Premium layout) */}
        <div style={{ flex: '2 1 600px', display: 'flex', flexDirection: 'column', gap: 16 }}>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <h2 style={{ fontSize: 20, fontWeight: 800 }}>Orchestration Registry ({data?.agents.length || 0})</h2>
            <span className="badge badge-blue">Pipeline Operational</span>
          </div>

          {data?.agents.map((agent: SystemAgent) => {
            const isActive = agent.status === 'active';
            return (
              <div key={agent.id} className="card" style={{
                padding: '24px 28px',
                borderLeft: isActive ? '4px solid var(--primary)' : '4px solid var(--text-muted)',
                background: 'var(--bg-card)',
                transition: 'transform 0.2s, border-color 0.2s',
                display: 'flex',
                flexDirection: 'column',
                gap: 16
              }}>
                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <h3 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>{agent.name}</h3>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                      <span className="text-mono" style={{ fontSize: 11, color: 'var(--text-muted)', background: 'rgba(255,255,255,0.03)', padding: '2px 6px', borderRadius: 4 }}>
                        ID: {agent.id}
                      </span>
                      <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>•</span>
                      <span style={{ fontSize: 12, color: 'var(--primary-light)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        {agent.role}
                      </span>
                    </div>
                  </div>
                  <span className={`badge ${isActive ? 'badge-low' : 'badge-critical'}`}>
                    {agent.status}
                  </span>
                </div>

                {/* Body */}
                <p className="text-secondary" style={{ fontSize: 14, lineHeight: 1.6 }}>
                  {agent.description}
                </p>

                {/* Technical Meta info */}
                <div style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 20,
                  fontSize: 12,
                  paddingTop: 12,
                  borderTop: '1px solid rgba(255, 255, 255, 0.04)',
                  color: 'var(--text-secondary)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <FileCode style={{ width: 14, height: 14, color: 'var(--text-muted)' }} />
                    <span>Prompt Template:</span>
                    <span className="text-mono" style={{ color: 'var(--text-primary)' }}>{agent.prompt_file}</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Cpu style={{ width: 14, height: 14, color: 'var(--text-muted)' }} />
                    <span>LLM Engine:</span>
                    <span className="text-mono" style={{ color: 'var(--accent-cyan)' }}>{data.active_model}</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Key style={{ width: 14, height: 14, color: 'var(--text-muted)' }} />
                    <span>Credential context:</span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>System Default</span>
                  </div>
                </div>

              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
}
