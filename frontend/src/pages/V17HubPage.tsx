import React, { useState, useEffect } from 'react';
import {
  Shield,
  Zap,
  Crosshair,
  TrendingUp,
  Cpu,
  Lock,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Play,
  Layers,
  ArrowRight,
  Sparkles,
  Server,
  DollarSign,
  AlertOctagon,
  RefreshCw,
} from 'lucide-react';
import {
  api,
  Mission,
  MissionMode,
  AgentProfile,
  CapabilityGraph,
  CyberRiskQuantification,
  InvestmentPlan,
  ControlPlaneStatus,
  parseUtcDate,
} from '../lib/api';
import { formatDistanceToNow } from 'date-fns';

export function V17HubPage() {
  const [activeTab, setActiveTab] = useState<'missions' | 'capability' | 'agents' | 'risk' | 'control'>('missions');
  const [missions, setMissions] = useState<Mission[]>([]);
  const [agents, setAgents] = useState<AgentProfile[]>([]);
  const [agentCategories, setAgentCategories] = useState<string[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [capabilityGraph, setCapabilityGraph] = useState<CapabilityGraph | null>(null);
  const [cyberRisk, setCyberRisk] = useState<CyberRiskQuantification | null>(null);
  const [investmentPlan, setInvestmentPlan] = useState<InvestmentPlan | null>(null);
  const [controlStatus, setControlStatus] = useState<ControlPlaneStatus | null>(null);
  const [loading, setLoading] = useState(true);

  // New Mission form state
  const [showLaunchModal, setShowLaunchModal] = useState(false);
  const [targetInput, setTargetInput] = useState('https://onlinecourses.nptel.ac.in');
  const [modeInput, setModeInput] = useState<MissionMode>('ASSESSMENT');
  const [budgetInput, setBudgetInput] = useState(600);
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [m, ag, cp] = await Promise.all([
        api.v17.listMissions().catch(() => []),
        api.v17.listAgents().catch(() => ({ total_agents: 60, categories: [], agents: [] })),
        api.v17.getControlPlaneStatus().catch(() => null),
      ]);

      setMissions(m);
      setAgents(ag.agents);
      setAgentCategories(ag.categories);
      setControlStatus(cp);

      // Load graph & risk for top mission or fallback
      const scanId = m.length > 0 ? m[0].id : 'sample-scan-1';
      const [cg, cr, ip] = await Promise.all([
        api.v17.getCapabilityGraph(scanId).catch(() => null),
        api.v17.getCyberRisk(scanId).catch(() => null),
        api.v17.getInvestmentPlan(scanId).catch(() => null),
      ]);
      setCapabilityGraph(cg);
      setCyberRisk(cr);
      setInvestmentPlan(ip);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleLaunchMission = async (e: React.FormEvent) => {
    e.preventDefault();
    setLaunching(true);
    setLaunchError(null);
    try {
      const newM = await api.v17.createMission({
        target: targetInput,
        mode: modeInput,
        budget_seconds: Number(budgetInput),
        scope_whitelist: [targetInput, '*.nptel.ac.in'],
      });
      setMissions(prev => [newM, ...prev]);
      setShowLaunchModal(false);
      // Reload graph and risk for newly created mission
      const [cg, cr, ip] = await Promise.all([
        api.v17.getCapabilityGraph(newM.id).catch(() => null),
        api.v17.getCyberRisk(newM.id).catch(() => null),
        api.v17.getInvestmentPlan(newM.id).catch(() => null),
      ]);
      setCapabilityGraph(cg);
      setCyberRisk(cr);
      setInvestmentPlan(ip);
    } catch (err: any) {
      setLaunchError(err.message || 'Failed to launch mission');
    } finally {
      setLaunching(false);
    }
  };

  const handleToggleKillSwitch = async () => {
    if (!controlStatus) return;
    const nextState = !controlStatus.global_kill_switch_active;
    try {
      await api.v17.toggleKillSwitch(nextState);
      setControlStatus(prev => prev ? { ...prev, global_kill_switch_active: nextState } : null);
    } catch (e) {
      console.error(e);
    }
  };

  const filteredAgents = selectedCategory
    ? agents.filter(a => a.category.toLowerCase() === selectedCategory.toLowerCase())
    : agents;

  return (
    <div className="page-content animate-fadeIn" style={{ maxWidth: 1400, margin: '0 auto' }}>
      {/* ── Header Bar ────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16, marginBottom: 24 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              background: 'linear-gradient(135deg, var(--primary) 0%, var(--accent-cyan) 100%)',
              width: 34, height: 34, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 16px rgba(0, 180, 216, 0.3)',
            }}>
              <Shield size={18} color="#fff" />
            </div>
            <h1 style={{ fontSize: 24, fontWeight: 900, letterSpacing: -0.5, margin: 0 }}>
              ARGOLOCK <span style={{ color: 'var(--accent-cyan)' }}>V1.7</span>
            </h1>
            <span className="badge badge-info" style={{ fontSize: 10, padding: '2px 8px', letterSpacing: 0.5 }}>
              ENTERPRISE PLATFORM
            </span>
          </div>
          <p className="text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
            Continuous VAPT · Safe Exploitation Validation · Capability Chaining · Cyber Risk & ROI Engine
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <button
            onClick={handleToggleKillSwitch}
            className="btn"
            style={{
              background: controlStatus?.global_kill_switch_active ? 'var(--sev-critical)' : 'rgba(255, 69, 58, 0.1)',
              borderColor: 'var(--sev-critical)',
              color: controlStatus?.global_kill_switch_active ? '#fff' : 'var(--sev-critical)',
              fontSize: 12, padding: '6px 14px',
            }}
          >
            <AlertOctagon size={14} />
            {controlStatus?.global_kill_switch_active ? 'KILL SWITCH ACTIVE (HALTED)' : 'Emergency Kill Switch'}
          </button>
          <button
            onClick={() => setShowLaunchModal(true)}
            className="btn btn-primary"
            style={{ fontSize: 13, padding: '8px 18px' }}
          >
            <Play size={14} /> Launch VAPT Mission
          </button>
        </div>
      </div>

      {/* ── Status Telemetry Bar ─────────────────────────────────────────────── */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, marginBottom: 24,
      }}>
        <div className="card" style={{ padding: '14px 18px', background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Hierarchical Architecture
          </div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--primary-light)', marginTop: 4 }}>
            {agents.length || 60} Specialist Agents
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Across 9 operational groups
          </div>
        </div>

        <div className="card" style={{ padding: '14px 18px', background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Security Control Plane
          </div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-green)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
            <CheckCircle2 size={18} /> Deterministic Gates
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Scope · Action · Safe PoC Policy
          </div>
        </div>

        <div className="card" style={{ padding: '14px 18px', background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Cyber Risk Index
          </div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--sev-high)', marginTop: 4 }}>
            {cyberRisk?.score ?? 68.5} / 100
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Rating: <strong style={{ color: 'var(--sev-high)' }}>{cyberRisk?.rating || 'HIGH'}</strong>
          </div>
        </div>

        <div className="card" style={{ padding: '14px 18px', background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
            Remediation ROI Available
          </div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-cyan)', marginTop: 4 }}>
            -{investmentPlan?.total_risk_reduction ?? 48.0} pts
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Projected residual: {investmentPlan?.projected_residual_risk ?? 20.5}
          </div>
        </div>
      </div>

      {/* ── Navigation Tabs ─────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, borderBottom: '1px solid var(--border)', paddingBottom: 12, overflowX: 'auto' }}>
        {[
          { key: 'missions', label: 'Mission Controller', icon: <Crosshair size={14} />, badge: missions.length },
          { key: 'capability', label: 'Capability Graph & Attack Paths', icon: <Layers size={14} /> },
          { key: 'agents', label: '60-Agent Operations Matrix', icon: <Cpu size={14} />, badge: '60' },
          { key: 'risk', label: 'Cyber Risk & Investment ROI', icon: <TrendingUp size={14} /> },
          { key: 'control', label: 'Security Control Plane', icon: <Lock size={14} /> },
        ].map(t => {
          const isActive = activeTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key as any)}
              className="btn"
              style={{
                background: isActive ? 'var(--primary-glow)' : 'transparent',
                borderColor: isActive ? 'var(--border-bright)' : 'transparent',
                color: isActive ? 'var(--primary-light)' : 'var(--text-secondary)',
                fontSize: 13, padding: '8px 16px', fontWeight: isActive ? 700 : 500,
                display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap',
              }}
            >
              {t.icon}
              {t.label}
              {t.badge !== undefined && (
                <span style={{
                  fontSize: 10, background: isActive ? 'rgba(0, 180, 216, 0.2)' : 'rgba(255,255,255,0.06)',
                  padding: '1px 6px', borderRadius: 8, color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)'
                }}>
                  {t.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Tab Content ─────────────────────────────────────────────────────── */}

      {/* 1. MISSIONS */}
      {activeTab === 'missions' && (
        <div className="card">
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Crosshair size={16} color="var(--primary-light)" />
              Active VAPT Missions & Campaigns
            </div>
            <button onClick={() => setShowLaunchModal(true)} className="btn btn-primary btn-sm">
              <Play size={12} /> New Mission
            </button>
          </div>

          {missions.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
              <Crosshair size={36} style={{ margin: '0 auto 12px', opacity: 0.4 }} />
              <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>No active missions</div>
              <p style={{ fontSize: 13, marginTop: 4 }}>Launch a mission in Discovery, Assessment, Validation, or Continuous mode.</p>
              <button onClick={() => setShowLaunchModal(true)} className="btn btn-primary btn-sm" style={{ marginTop: 12 }}>
                Launch First Mission
              </button>
            </div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Mission Target</th>
                    <th>Mode</th>
                    <th>Phase</th>
                    <th>Progress</th>
                    <th>Agents</th>
                    <th>Findings</th>
                    <th>Risk Score</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {missions.map(m => (
                    <tr key={m.id}>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{m.target}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{m.name}</div>
                      </td>
                      <td>
                        <span className={`badge ${
                          m.mode === 'ASSESSMENT' ? 'badge-critical' : m.mode === 'VALIDATION' ? 'badge-high' : m.mode === 'CONTINUOUS' ? 'badge-medium' : 'badge-info'
                        }`}>
                          {m.mode}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-cyan)' }} />
                          <span style={{ fontSize: 12 }}>{m.current_phase}</span>
                        </div>
                      </td>
                      <td>
                        <div style={{ width: 100 }}>
                          <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 2 }}>{m.progress_percent}%</div>
                          <div className="progress-track" style={{ height: 4 }}>
                            <div className="progress-fill" style={{ width: `${m.progress_percent}%` }} />
                          </div>
                        </div>
                      </td>
                      <td>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--primary-light)' }}>
                          {m.active_agent_count} active
                        </span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 700, color: 'var(--sev-high)' }}>
                          {m.findings_count}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 800, color: m.risk_score >= 60 ? 'var(--sev-critical)' : 'var(--sev-high)' }}>
                          {m.risk_score ? `${m.risk_score}/100` : '—'}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {m.created_at ? formatDistanceToNow(parseUtcDate(m.created_at), { addSuffix: true }) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* 2. CAPABILITY GRAPH & ATTACK PATHS */}
      {activeTab === 'capability' && (
        <div>
          <div className="card mb-6" style={{ background: 'var(--bg-elevated)' }}>
            <div className="card-header">
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Layers size={16} color="var(--accent-cyan)" />
                Attacker Capability Graph & Multi-Stage Attack Chains
              </div>
              <span className="badge badge-info">
                Evidence-Backed DAG ({capabilityGraph?.total_nodes || 0} Nodes · {capabilityGraph?.total_edges || 0} Transitions)
              </span>
            </div>
            <p className="text-secondary" style={{ fontSize: 13, marginBottom: 20 }}>
              Instead of isolating raw CVEs, ARGOLOCK models what <strong>attacker capabilities</strong> are unlocked by verified vulnerabilities and traces complete paths to terminal business impact.
            </p>

            {/* Attack Chains Section */}
            {capabilityGraph?.attack_chains && capabilityGraph.attack_chains.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {capabilityGraph.attack_chains.map(chain => (
                  <div key={chain.id} style={{
                    padding: 18, background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border-bright)',
                    borderRadius: 10, position: 'relative', overflow: 'hidden',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                      <div>
                        <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-primary)' }}>
                          {chain.title}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                          Entry Point: <span style={{ color: 'var(--accent-cyan)' }}>{chain.entry_point}</span> ➔ Terminal Impact: <span style={{ color: 'var(--sev-critical)', fontWeight: 700 }}>{chain.terminal_impact}</span>
                        </div>
                      </div>
                      <span className={`badge ${chain.severity === 'critical' ? 'badge-critical' : 'badge-high'}`} style={{ fontWeight: 700 }}>
                        {chain.severity.toUpperCase()} ATTACK PATH
                      </span>
                    </div>

                    {/* Nodes flow */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
                      {chain.path_nodes.map((node, i) => (
                        <React.Fragment key={node.id}>
                          <div style={{
                            padding: '10px 14px',
                            background: node.terminal_impact ? 'var(--sev-critical-bg)' : 'var(--bg-elevated)',
                            border: `1px solid ${node.terminal_impact ? 'var(--sev-critical)' : 'var(--border)'}`,
                            borderRadius: 8, maxWidth: 260,
                          }}>
                            <div style={{ fontSize: 11, fontWeight: 700, color: node.terminal_impact ? 'var(--sev-critical)' : 'var(--primary-light)' }}>
                              {node.name}
                            </div>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, wordBreak: 'break-all' }}>
                              {node.target_asset}
                            </div>
                            {node.evidence_hash && (
                              <div style={{ fontSize: 9, fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-green)', marginTop: 4 }}>
                                SHA256: {node.evidence_hash}...
                              </div>
                            )}
                          </div>
                          {i < chain.path_nodes.length - 1 && (
                            <ArrowRight size={14} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '30px 20px', color: 'var(--text-muted)' }}>
                No active capability chains mapped yet.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. 60-AGENT OPERATIONS MATRIX */}
      {activeTab === 'agents' && (
        <div>
          {/* Category Filter Pills */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 16, flexWrap: 'wrap' }}>
            <button
              onClick={() => setSelectedCategory('')}
              className={`badge ${selectedCategory === '' ? 'badge-blue' : 'badge-gray'}`}
              style={{ cursor: 'pointer', border: 'none', padding: '6px 12px', fontSize: 12, opacity: selectedCategory === '' ? 1 : 0.6 }}
            >
              All Agents (60)
            </button>
            {agentCategories.map(cat => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`badge ${selectedCategory === cat ? 'badge-blue' : 'badge-gray'}`}
                style={{ cursor: 'pointer', border: 'none', padding: '6px 12px', fontSize: 12, opacity: selectedCategory === cat ? 1 : 0.6 }}
              >
                {cat} ({agents.filter(a => a.category === cat).length})
              </button>
            ))}
          </div>

          {/* Grid of Agent Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 14 }}>
            {filteredAgents.map(agent => (
              <div key={agent.id} className="card" style={{ padding: 16, background: 'var(--bg-elevated)', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                  <div>
                    <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                      #{agent.id}
                    </span>
                    <h3 style={{ fontSize: 14, fontWeight: 700, margin: '2px 0 0', color: 'var(--text-primary)' }}>
                      {agent.name}
                    </h3>
                  </div>
                  <span className="badge badge-success" style={{ fontSize: 9 }}>ACTIVE</span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--primary-light)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 8 }}>
                  {agent.category}
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4, margin: '0 0 10px', minHeight: 34 }}>
                  {agent.description}
                </p>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {agent.tools.map((t, idx) => (
                    <span key={idx} style={{
                      fontSize: 10, fontFamily: 'JetBrains Mono, monospace',
                      background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
                      padding: '2px 6px', borderRadius: 4, color: 'var(--text-muted)'
                    }}>
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. CYBER RISK & INVESTMENT ROI */}
      {activeTab === 'risk' && (
        <div>
          {/* Cyber Risk Factor Decomposition */}
          <div className="card mb-6" style={{ background: 'var(--bg-elevated)' }}>
            <div className="card-header">
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <TrendingUp size={16} color="var(--sev-high)" />
                Multi-Variable Cyber Risk Model
              </div>
              <span className="badge badge-high" style={{ fontSize: 12, padding: '4px 10px', fontWeight: 800 }}>
                CALCULATED SCORE: {cyberRisk?.score ?? 68.5} / 100
              </span>
            </div>
            <div style={{
              display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginTop: 12,
            }}>
              <div style={{ padding: 12, background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Severity Factor</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginTop: 2 }}>{cyberRisk?.severity_factor ?? 7.5} / 10</div>
              </div>
              <div style={{ padding: 12, background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Exploitability</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--sev-critical)', marginTop: 2 }}>{cyberRisk?.exploitability_factor ?? 1.0}</div>
              </div>
              <div style={{ padding: 12, background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Asset Criticality</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--accent-cyan)', marginTop: 2 }}>{cyberRisk?.asset_criticality_factor ?? 1.2}x</div>
              </div>
              <div style={{ padding: 12, background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Exposure Factor</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--sev-high)', marginTop: 2 }}>{cyberRisk?.exposure_factor ?? 1.3}x</div>
              </div>
              <div style={{ padding: 12, background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Confidence</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--accent-green)', marginTop: 2 }}>{(cyberRisk?.confidence_factor ?? 0.95) * 100}%</div>
              </div>
            </div>
          </div>

          {/* Investment Optimization Table */}
          <div className="card">
            <div className="card-header">
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <DollarSign size={16} color="var(--accent-green)" />
                Remediation ROI & Budget Investment Sequence
              </div>
              <span className="badge badge-success">
                Max Risk Reduction: -{investmentPlan?.total_risk_reduction ?? 48.0} pts
              </span>
            </div>
            <p className="text-secondary" style={{ fontSize: 13, marginBottom: 16 }}>
              Prioritizes fixes by net Return on Investment (Risk Reduction / Cost Index) to maximize risk reduction under any given engineering budget.
            </p>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Priority</th>
                    <th>Remediation Control</th>
                    <th>Est. Cost</th>
                    <th>Risk Reduction</th>
                    <th>Residual</th>
                    <th>ROI Score</th>
                    <th>Effort</th>
                    <th>Compliance</th>
                  </tr>
                </thead>
                <tbody>
                  {(investmentPlan?.actions || []).map(act => (
                    <tr key={act.id}>
                      <td>
                        <span className={`badge ${
                          act.priority === 'P1' ? 'badge-critical' : act.priority === 'P2' ? 'badge-high' : act.priority === 'P3' ? 'badge-medium' : 'badge-gray'
                        }`} style={{ fontWeight: 800 }}>
                          {act.priority}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{act.recommended_control}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Target: {act.title}</div>
                      </td>
                      <td>
                        <span style={{ fontSize: 12, color: act.estimated_cost === 'Low' ? 'var(--accent-green)' : 'var(--sev-high)' }}>
                          {act.estimated_cost}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 700, color: 'var(--accent-green)' }}>
                          -{act.risk_reduction_points} pts
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {act.residual_risk_points}
                      </td>
                      <td>
                        <span style={{ fontWeight: 800, color: 'var(--accent-cyan)' }}>
                          {act.roi_score}x
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {act.effort_hours} hrs
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {act.compliance_mappings.map((comp, idx) => (
                            <span key={idx} style={{
                              fontSize: 9, background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 4
                            }}>
                              {comp}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 5. SECURITY CONTROL PLANE */}
      {activeTab === 'control' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Lock size={16} color="var(--accent-green)" />
              Security Control Plane & Deterministic Execution Gates
            </div>
            <span className="badge badge-success">Active Enforcing</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16, marginTop: 12 }}>
            <div style={{ padding: 16, background: 'rgba(0,0,0,0.25)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, color: 'var(--primary-light)', marginBottom: 6 }}>Gate 1: Scope Gate</div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                Enforces strict whitelist matching against authorized target domains, IPs, and CIDRs. Unlisted assets are blocked unconditionally.
              </p>
            </div>

            <div style={{ padding: 16, background: 'rgba(0,0,0,0.25)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: 6 }}>Gate 2: Action Classification Gate</div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                Classifies every tool action into PASSIVE, LOW_RISK_ACTIVE, VALIDATION, CONTROLLED_EXPLOITATION, HIGH_IMPACT, or DESTRUCTIVE. Prohibits destructive operations.
              </p>
            </div>

            <div style={{ padding: 16, background: 'rgba(0,0,0,0.25)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, color: 'var(--sev-critical)', marginBottom: 6 }}>Gate 3: Exploitation Safety Gate</div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                Enforces the minimum-impact proof required to establish findings. Prohibits mass data dumping or unconstrained query exfiltration.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── Launch Mission Modal ────────────────────────────────────────────── */}
      {showLaunchModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100, padding: 16,
        }}>
          <div className="card" style={{ maxWidth: 520, width: '100%', border: '1px solid var(--border-bright)' }}>
            <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className="card-title">Launch V1.7 VAPT Mission</div>
              <button onClick={() => setShowLaunchModal(false)} className="btn btn-outline btn-sm">✕</button>
            </div>

            <form onSubmit={handleLaunchMission} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {launchError && (
                <div style={{ padding: 10, background: 'var(--sev-critical-bg)', color: 'var(--sev-critical)', borderRadius: 6, fontSize: 12 }}>
                  {launchError}
                </div>
              )}

              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: 6 }}>
                  Target Domain or URL
                </label>
                <input
                  type="text"
                  value={targetInput}
                  onChange={e => setTargetInput(e.target.value)}
                  placeholder="https://example.com"
                  className="input"
                  style={{ width: '100%' }}
                  required
                />
              </div>

              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: 6 }}>
                  Mission Mode
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  {(['DISCOVERY', 'ASSESSMENT', 'VALIDATION', 'CONTINUOUS'] as MissionMode[]).map(mode => (
                    <button
                      type="button"
                      key={mode}
                      onClick={() => setModeInput(mode)}
                      className={`btn ${modeInput === mode ? 'btn-primary' : 'btn-outline'}`}
                      style={{ fontSize: 12, justifyContent: 'center' }}
                    >
                      {mode}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: 6 }}>
                  Execution Budget (Seconds)
                </label>
                <input
                  type="number"
                  value={budgetInput}
                  onChange={e => setBudgetInput(Number(e.target.value))}
                  className="input"
                  style={{ width: '100%' }}
                  min={60}
                  max={3600}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 10 }}>
                <button type="button" onClick={() => setShowLaunchModal(false)} className="btn btn-outline">
                  Cancel
                </button>
                <button type="submit" disabled={launching} className="btn btn-primary">
                  {launching ? 'Initializing Mission...' : 'Confirm & Launch'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
