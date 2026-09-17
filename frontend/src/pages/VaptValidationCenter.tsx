import React, { useState, useEffect } from 'react';
import {
  ShieldCheck, ShieldAlert, CheckCircle, AlertTriangle, XCircle,
  FileCheck, Lock, Activity, Eye, Play, RotateCw, Check, X,
  Terminal, Server, ChevronRight, Hash, Layers, Network
} from 'lucide-react';
import { api, Finding } from '../lib/api';

export function VaptValidationCenter() {
  const [activeTab, setActiveTab] = useState<'pipeline' | 'assets' | 'approvals' | 'attack_paths' | 'tools_audit'>('pipeline');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [authorizations, setAuthorizations] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [toolsHealth, setToolsHealth] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [attackPathGraph, setAttackPathGraph] = useState<any>(null);
  const [mitreMappings, setMitreMappings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Modals state
  const [selectedEvidence, setSelectedEvidence] = useState<any>(null);
  const [selectedRisk, setSelectedRisk] = useState<any>(null);
  const [selectedRemediation, setSelectedRemediation] = useState<any>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // New authorization form state
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [newAuth, setNewAuth] = useState({
    asset_id: '',
    hostname_or_ip: '',
    owner: '',
    scope: '',
    permitted_ports: '80, 443, 8080',
    permitted_services: 'http, https',
    assessment_id: 'assess-primary',
    approval_reference: 'AUTH-VAPT-2026',
  });

  const loadData = async () => {
    setLoading(true);
    try {
      const [fRes, authRes, appRes, toolsRes, auditRes, apRes, mitreRes] = await Promise.allSettled([
        api.findings.list({ limit: 100 }),
        api.vapt.getAuthorizations(),
        api.vapt.getApprovals(),
        api.vapt.getToolsHealth(),
        api.vapt.getAuditTrail(30),
        api.vapt.getAttackPaths(),
        api.vapt.getMitreMappings(),
      ]);

      if (fRes.status === 'fulfilled') setFindings(fRes.value.findings || []);
      if (authRes.status === 'fulfilled') setAuthorizations(authRes.value || []);
      if (appRes.status === 'fulfilled') setApprovals(appRes.value || []);
      if (toolsRes.status === 'fulfilled') setToolsHealth(toolsRes.value || []);
      if (auditRes.status === 'fulfilled') setAuditLogs(auditRes.value || []);
      if (apRes.status === 'fulfilled') setAttackPathGraph(apRes.value);
      if (mitreRes.status === 'fulfilled') setMitreMappings(mitreRes.value || []);
    } catch (e) {
      console.error('Failed loading VAPT data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleValidate = async (findingId: string, level = 'level_1', approvalId?: string) => {
    setActionLoading(findingId);
    try {
      const res = await api.vapt.validateFinding(findingId, level, approvalId);
      alert(`Validation Complete: ${res.validation_status.toUpperCase()}\n${res.rationale}`);
      await loadData();
    } catch (e: any) {
      alert(`Validation Error: ${e.message || e}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleRetest = async (findingId: string) => {
    setActionLoading(findingId);
    try {
      const res = await api.vapt.retestFinding(findingId);
      alert(`Retest Result: ${res.retest_status.toUpperCase()}\n${res.comparison_summary}`);
      await loadData();
    } catch (e: any) {
      alert(`Retest Error: ${e.message || e}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleViewEvidence = async (findingId: string) => {
    try {
      const res = await api.vapt.getEvidence(findingId);
      setSelectedEvidence(res);
    } catch (e: any) {
      alert(`Error fetching evidence: ${e.message || e}`);
    }
  };

  const handleViewRisk = async (findingId: string) => {
    try {
      const res = await api.vapt.getRisk(findingId);
      setSelectedRisk(res);
    } catch (e: any) {
      alert(`Error fetching risk breakdown: ${e.message || e}`);
    }
  };

  const handleViewRemediation = async (findingId: string) => {
    try {
      const res = await api.vapt.getRemediationPlan(findingId);
      setSelectedRemediation(res);
    } catch (e: any) {
      alert(`Error fetching remediation: ${e.message || e}`);
    }
  };

  const handleApprove = async (approvalId: string) => {
    try {
      await api.vapt.approve(approvalId, 'Operator approved from VAPT Center');
      await loadData();
    } catch (e: any) {
      alert(`Approval error: ${e.message || e}`);
    }
  };

  const handleReject = async (approvalId: string) => {
    try {
      await api.vapt.reject(approvalId, 'Operator rejected from VAPT Center');
      await loadData();
    } catch (e: any) {
      alert(`Reject error: ${e.message || e}`);
    }
  };

  const handleCreateAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const ports = newAuth.permitted_ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
      const services = newAuth.permitted_services.split(',').map(s => s.trim()).filter(Boolean);
      const scope = newAuth.scope ? newAuth.scope.split(',').map(s => s.trim()) : [newAuth.hostname_or_ip];

      await api.vapt.createAuthorization({
        asset_id: newAuth.asset_id || `asset-${Date.now().toString().slice(-4)}`,
        hostname_or_ip: newAuth.hostname_or_ip,
        owner: newAuth.owner || 'Security Ops',
        authorization_status: 'authorized',
        scope,
        permitted_ports: ports.length ? ports : [80, 443],
        permitted_services: services.length ? services : ['http', 'https'],
        assessment_id: newAuth.assessment_id,
        approval_reference: newAuth.approval_reference,
      });

      setShowAuthModal(false);
      setNewAuth({
        asset_id: '',
        hostname_or_ip: '',
        owner: '',
        scope: '',
        permitted_ports: '80, 443, 8080',
        permitted_services: 'http, https',
        assessment_id: 'assess-primary',
        approval_reference: 'AUTH-VAPT-2026',
      });
      await loadData();
    } catch (e: any) {
      alert(`Failed creating authorization: ${e.message || e}`);
    }
  };

  // Stats calculation
  const totalFindings = findings.length;
  const confirmedCount = findings.filter(f => (f as any).validation_status === 'confirmed' || f.confirmed).length;
  const validatedCount = findings.filter(f => (f as any).validation_status === 'validated').length;
  const fpCount = findings.filter(f => (f as any).validation_status === 'false_positive' || f.false_positive).length;
  const pendingApprovalsCount = approvals.filter(a => a.status === 'pending').length;

  return (
    <div className="page-content animate-fadeIn" style={{ maxWidth: 1400, margin: '0 auto', paddingBottom: 60 }}>
      {/* Top Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(92, 98, 236, 0.12) 0%, rgba(0, 212, 255, 0.06) 100%)',
        border: '1px solid var(--border-bright)',
        borderRadius: 'var(--radius)',
        padding: '24px 28px',
        marginBottom: 24,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 16,
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldCheck style={{ width: 28, height: 28, color: 'var(--accent-cyan)' }} />
            <h1 style={{ fontSize: 24, fontWeight: 900, letterSpacing: '-0.5px' }}>
              ARGOLOCK NET VAPT Validation & Security Testing Orchestrator
            </h1>
          </div>
          <p style={{ color: 'var(--text-secondary)', marginTop: 6, fontSize: 13 }}>
            Controlled, evidence-driven vulnerability validation, tamper-evident SHA-256 hashing, and contextual cyber risk quantification.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={() => setShowAuthModal(true)}
            style={{
              background: 'var(--primary)',
              color: '#fff',
              border: 'none',
              padding: '9px 18px',
              borderRadius: 'var(--radius-sm)',
              fontWeight: 600,
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: '0 0 15px var(--primary-glow)'
            }}
          >
            <Lock style={{ width: 15, height: 15 }} />
            <span>Authorize Target Asset</span>
          </button>
          <button
            onClick={loadData}
            style={{
              background: 'var(--bg-elevated)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border)',
              padding: '9px 14px',
              borderRadius: 'var(--radius-sm)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            <RotateCw style={{ width: 14, height: 14 }} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: 14,
        marginBottom: 24,
      }}>
        <div className="card" style={{ padding: '16px 20px', background: 'var(--bg-card)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Total Findings</div>
          <div style={{ fontSize: 26, fontWeight: 900, marginTop: 4 }}>{totalFindings}</div>
        </div>
        <div className="card" style={{ padding: '16px 20px', background: 'var(--bg-card)' }}>
          <div style={{ fontSize: 11, color: 'var(--sev-low)', textTransform: 'uppercase', fontWeight: 700 }}>Confirmed Exploitable</div>
          <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--sev-critical)', marginTop: 4 }}>{confirmedCount}</div>
        </div>
        <div className="card" style={{ padding: '16px 20px', background: 'var(--bg-card)' }}>
          <div style={{ fontSize: 11, color: 'var(--accent-cyan)', textTransform: 'uppercase', fontWeight: 700 }}>Corroborated / Validated</div>
          <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--accent-cyan)', marginTop: 4 }}>{validatedCount}</div>
        </div>
        <div className="card" style={{ padding: '16px 20px', background: 'var(--bg-card)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>False Positives Screened</div>
          <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--text-secondary)', marginTop: 4 }}>{fpCount}</div>
        </div>
        <div className="card" style={{ padding: '16px 20px', background: 'var(--bg-card)' }}>
          <div style={{ fontSize: 11, color: 'var(--sev-high)', textTransform: 'uppercase', fontWeight: 700 }}>Pending Approvals</div>
          <div style={{ fontSize: 26, fontWeight: 900, color: 'var(--sev-high)', marginTop: 4 }}>{pendingApprovalsCount}</div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div style={{
        display: 'flex',
        gap: 8,
        borderBottom: '1px solid var(--border)',
        marginBottom: 20,
        paddingBottom: 2,
      }}>
        {[
          { key: 'pipeline', label: 'Validation Pipeline', icon: Activity },
          { key: 'assets', label: `Authorized Assets (${authorizations.length})`, icon: Lock },
          { key: 'approvals', label: `Testing Approvals (${approvals.length})`, icon: ShieldCheck },
          { key: 'attack_paths', label: 'Attack Paths & MITRE', icon: Network },
          { key: 'tools_audit', label: 'Tool Health & Audit Logs', icon: Terminal },
        ].map(t => {
          const Icon = t.icon;
          const isActive = activeTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key as any)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 18px',
                background: isActive ? 'var(--bg-card)' : 'transparent',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--primary)' : '2px solid transparent',
                borderRadius: '8px 8px 0 0',
                color: isActive ? '#fff' : 'var(--text-secondary)',
                fontWeight: isActive ? 700 : 500,
                fontSize: 13,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Icon style={{ width: 16, height: 16, color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)' }} />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: VALIDATION PIPELINE */}
      {activeTab === 'pipeline' && (
        <div>
          {loading ? (
            <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>Loading findings pipeline...</div>
          ) : findings.length === 0 ? (
            <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)' }}>
              No vulnerabilities identified yet. Run an authorized scan or register candidate findings.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {findings.map((f: any) => {
                const valStatus = f.validation_status || (f.confirmed ? 'confirmed' : 'detected');
                const isWorking = actionLoading === f.id;

                let statusBadge = <span className="badge badge-blue">DETECTED</span>;
                if (valStatus === 'confirmed') statusBadge = <span className="badge badge-critical">CONFIRMED</span>;
                else if (valStatus === 'validated') statusBadge = <span className="badge badge-high">VALIDATED</span>;
                else if (valStatus === 'false_positive') statusBadge = <span className="badge badge-info">FALSE POSITIVE</span>;
                else if (valStatus === 'not_exploitable') statusBadge = <span className="badge badge-low">NOT EXPLOITABLE</span>;
                else if (valStatus === 'requires_manual_review') statusBadge = <span className="badge badge-medium">REQUIRES REVIEW</span>;

                return (
                  <div key={f.id} className="card" style={{
                    padding: 20,
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 12
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                          <span style={{ fontWeight: 800, fontSize: 16 }}>{f.title}</span>
                          {statusBadge}
                          <span className={`badge badge-${f.severity}`}>{f.severity.toUpperCase()}</span>
                          {f.cve_ids && f.cve_ids.length > 0 && (
                            <span style={{ fontSize: 11, background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: 4, fontFamily: 'JetBrains Mono' }}>
                              {f.cve_ids.join(', ')}
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4, fontFamily: 'JetBrains Mono' }}>
                          {f.affected_endpoint || 'Target: Primary Host'}
                        </div>
                      </div>

                      {/* Action buttons */}
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <button
                          disabled={isWorking}
                          onClick={() => handleValidate(f.id, 'level_1')}
                          style={{
                            background: 'rgba(92, 98, 236, 0.15)',
                            border: '1px solid rgba(92, 98, 236, 0.35)',
                            color: '#a5b4fc',
                            padding: '6px 12px',
                            borderRadius: 'var(--radius-sm)',
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 5
                          }}
                        >
                          <Play style={{ width: 13, height: 13 }} />
                          <span>{isWorking ? 'Validating...' : 'Validate (Level 1)'}</span>
                        </button>

                        <button
                          onClick={() => handleViewEvidence(f.id)}
                          style={{
                            background: 'var(--bg-elevated)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-secondary)',
                            padding: '6px 12px',
                            borderRadius: 'var(--radius-sm)',
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 5
                          }}
                        >
                          <Hash style={{ width: 13, height: 13 }} />
                          <span>Evidence & Hash</span>
                        </button>

                        <button
                          onClick={() => handleViewRisk(f.id)}
                          style={{
                            background: 'var(--bg-elevated)',
                            border: '1px solid var(--border)',
                            color: 'var(--accent-cyan)',
                            padding: '6px 12px',
                            borderRadius: 'var(--radius-sm)',
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 5
                          }}
                        >
                          <Activity style={{ width: 13, height: 13 }} />
                          <span>Explain Risk</span>
                        </button>

                        <button
                          onClick={() => handleViewRemediation(f.id)}
                          style={{
                            background: 'var(--bg-elevated)',
                            border: '1px solid var(--border)',
                            color: 'var(--accent-green)',
                            padding: '6px 12px',
                            borderRadius: 'var(--radius-sm)',
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 5
                          }}
                        >
                          <FileCheck style={{ width: 13, height: 13 }} />
                          <span>Remediation</span>
                        </button>

                        <button
                          disabled={isWorking}
                          onClick={() => handleRetest(f.id)}
                          style={{
                            background: 'rgba(52, 211, 153, 0.1)',
                            border: '1px solid rgba(52, 211, 153, 0.3)',
                            color: '#6ee7b7',
                            padding: '6px 12px',
                            borderRadius: 'var(--radius-sm)',
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 5
                          }}
                        >
                          <RotateCw style={{ width: 13, height: 13 }} />
                          <span>Retest</span>
                        </button>
                      </div>
                    </div>

                    <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      {f.description}
                    </div>

                    {f.evidence_id && (
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        fontSize: 11,
                        background: 'rgba(0,0,0,0.3)',
                        padding: '6px 12px',
                        borderRadius: 6,
                        color: 'var(--text-muted)'
                      }}>
                        <CheckCircle style={{ width: 13, height: 13, color: 'var(--accent-cyan)' }} />
                        <span>Evidence Captured (ID: {f.evidence_id.slice(0, 8)}...)</span>
                        <span style={{ marginLeft: 'auto' }}>Source Tool: {f.tool_source || 'orchestrator'}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: AUTHORIZED ASSETS */}
      {activeTab === 'assets' && (
        <div className="card" style={{ padding: 24, background: 'var(--bg-card)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <div>
              <h2 style={{ fontSize: 18, fontWeight: 800 }}>Authorized Asset Scope & Testing Windows</h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                Zero-Trust Gate: Scans and validation tests are strictly prohibited against any host not in this registry.
              </p>
            </div>
            <button
              onClick={() => setShowAuthModal(true)}
              style={{
                background: 'var(--primary)',
                color: '#fff',
                border: 'none',
                padding: '8px 16px',
                borderRadius: 'var(--radius-sm)',
                fontWeight: 600,
                fontSize: 13,
                cursor: 'pointer'
              }}
            >
              + Register Asset
            </button>
          </div>

          {authorizations.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
              No assets authorized yet. Click "+ Register Asset" to define your authorized testing scope.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '10px 14px' }}>Asset ID</th>
                    <th style={{ padding: '10px 14px' }}>Hostname / Target</th>
                    <th style={{ padding: '10px 14px' }}>Owner</th>
                    <th style={{ padding: '10px 14px' }}>Status</th>
                    <th style={{ padding: '10px 14px' }}>Permitted Ports</th>
                    <th style={{ padding: '10px 14px' }}>Permitted Services</th>
                    <th style={{ padding: '10px 14px' }}>Approval Reference</th>
                  </tr>
                </thead>
                <tbody>
                  {authorizations.map(a => (
                    <tr key={a.asset_id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono', color: 'var(--accent-cyan)' }}>{a.asset_id}</td>
                      <td style={{ padding: '12px 14px', fontWeight: 600 }}>{a.hostname_or_ip}</td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-secondary)' }}>{a.owner}</td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="badge badge-low">{a.authorization_status.toUpperCase()}</span>
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                        {a.permitted_ports?.join(', ') || 'Default (80, 443)'}
                      </td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-secondary)' }}>
                        {a.permitted_services?.join(', ') || 'http, https'}
                      </td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-muted)', fontSize: 11 }}>{a.approval_reference}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: OPERATOR TESTING APPROVALS */}
      {activeTab === 'approvals' && (
        <div className="card" style={{ padding: 24, background: 'var(--bg-card)' }}>
          <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>Operator Testing Approvals</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 20 }}>
            Levels 2 & 3 (controlled proof-of-condition and advanced testing) require signed operator authorization.
          </p>

          {approvals.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
              No active testing approval requests pending.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '10px 14px' }}>Approval ID</th>
                    <th style={{ padding: '10px 14px' }}>Target Asset</th>
                    <th style={{ padding: '10px 14px' }}>Requested Level</th>
                    <th style={{ padding: '10px 14px' }}>Requested By</th>
                    <th style={{ padding: '10px 14px' }}>Justification</th>
                    <th style={{ padding: '10px 14px' }}>Status</th>
                    <th style={{ padding: '10px 14px' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {approvals.map(appr => (
                    <tr key={appr.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono', fontSize: 11 }}>{appr.id.slice(0, 8)}...</td>
                      <td style={{ padding: '12px 14px', fontWeight: 600 }}>{appr.asset_id}</td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="badge badge-medium">{appr.testing_level.toUpperCase()}</span>
                      </td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-secondary)' }}>{appr.requested_by}</td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-muted)', fontSize: 12 }}>{appr.scope_justification || 'Standard verification'}</td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className={`badge ${appr.status === 'approved' ? 'badge-low' : appr.status === 'rejected' ? 'badge-critical' : 'badge-high'}`}>
                          {appr.status.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        {appr.status === 'pending' && (
                          <div style={{ display: 'flex', gap: 6 }}>
                            <button
                              onClick={() => handleApprove(appr.id)}
                              style={{
                                background: 'rgba(52, 211, 153, 0.15)',
                                border: '1px solid rgba(52, 211, 153, 0.3)',
                                color: '#34d399',
                                padding: '4px 10px',
                                borderRadius: 4,
                                fontSize: 11,
                                fontWeight: 700,
                                cursor: 'pointer'
                              }}
                            >
                              Approve
                            </button>
                            <button
                              onClick={() => handleReject(appr.id)}
                              style={{
                                background: 'rgba(239, 68, 68, 0.15)',
                                border: '1px solid rgba(239, 68, 68, 0.3)',
                                color: '#f87171',
                                padding: '4px 10px',
                                borderRadius: 4,
                                fontSize: 11,
                                fontWeight: 700,
                                cursor: 'pointer'
                              }}
                            >
                              Reject
                            </button>
                          </div>
                        )}
                        {appr.status !== 'pending' && (
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            Decided by {appr.approved_by || 'Operator'}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: ATTACK PATHS & MITRE */}
      {activeTab === 'attack_paths' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Attack Path Topology Card */}
          <div className="card" style={{ padding: 24, background: 'var(--bg-card)' }}>
            <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>Attack Path Topology & Critical Asset Exposure</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 20 }}>
              Models potential traversal paths from public ingress to crown-jewel assets for contextual risk scoring.
            </p>

            {attackPathGraph && attackPathGraph.nodes && (
              <div style={{
                background: 'rgba(0,0,0,0.35)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: 24,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-around',
                flexWrap: 'wrap',
                gap: 16
              }}>
                {attackPathGraph.nodes.map((node: any, idx: number) => (
                  <React.Fragment key={node.node_id}>
                    <div style={{
                      background: node.node_type === 'critical_data' ? 'rgba(239, 68, 68, 0.15)' : 'var(--bg-elevated)',
                      border: node.node_type === 'critical_data' ? '1px solid var(--sev-critical)' : '1px solid var(--border-bright)',
                      borderRadius: 12,
                      padding: '16px 20px',
                      minWidth: 160,
                      textAlign: 'center'
                    }}>
                      <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
                        {node.node_type.replace('_', ' ')}
                      </div>
                      <div style={{ fontSize: 14, fontWeight: 800, marginTop: 4, color: node.node_type === 'critical_data' ? '#f87171' : 'var(--text-primary)' }}>
                        {node.name}
                      </div>
                    </div>
                    {idx < attackPathGraph.nodes.length - 1 && (
                      <ChevronRight style={{ color: 'var(--accent-cyan)', width: 24, height: 24 }} />
                    )}
                  </React.Fragment>
                ))}
              </div>
            )}
          </div>

          {/* MITRE ATT&CK Mapping Table */}
          <div className="card" style={{ padding: 24, background: 'var(--bg-card)' }}>
            <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>MITRE ATT&CK Framework Mapping</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 16 }}>
              Confirmed vulnerability behaviors classified into MITRE ATT&CK Enterprise tactics and techniques.
            </p>

            {mitreMappings.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 30, color: 'var(--text-muted)' }}>
                No confirmed findings mapped yet. Run non-destructive validation to confirm findings.
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                      <th style={{ padding: '10px 14px' }}>Technique ID</th>
                      <th style={{ padding: '10px 14px' }}>Technique Name</th>
                      <th style={{ padding: '10px 14px' }}>Tactic</th>
                      <th style={{ padding: '10px 14px' }}>Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mitreMappings.map((m, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono', color: 'var(--accent-cyan)' }}>{m.technique_id}</td>
                        <td style={{ padding: '10px 14px', fontWeight: 600 }}>{m.technique_name}</td>
                        <td style={{ padding: '10px 14px' }}>
                          <span className="badge badge-blue">{m.tactic}</span>
                        </td>
                        <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono' }}>{Math.round(m.confidence * 100)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: TOOL HEALTH & AUDIT TRAIL */}
      {activeTab === 'tools_audit' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Tool Adapter Health Matrix */}
          <div className="card" style={{ padding: 24, background: 'var(--bg-card)' }}>
            <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>Modular Tool Adapter Registry & Health</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 18 }}>
              Real-time health telemetry across all integrated security scanning and validation adapters.
            </p>

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: 14
            }}>
              {toolsHealth.map(t => (
                <div key={t.tool_id} style={{
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: 16
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 800, fontSize: 14 }}>{t.name}</span>
                    <span className={`badge ${t.health_status === 'READY' ? 'badge-low' : 'badge-medium'}`}>
                      {t.health_status}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                    Category: <span style={{ color: 'var(--text-secondary)' }}>{t.category}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                    Version: <span style={{ color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono' }}>{t.version}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                    Success Rate: <span style={{ color: 'var(--accent-green)' }}>{t.success_rate}%</span> ({t.execution_count} runs)
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Immutable Audit Trail Table */}
          <div className="card" style={{ padding: 24, background: 'var(--bg-card)' }}>
            <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>Immutable VAPT Audit Trail</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 16 }}>
              Tamper-evident, chained SHA-256 cryptographic logs documenting every action, authorization, and validation.
            </p>

            {auditLogs.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 30, color: 'var(--text-muted)' }}>
                No audit events recorded yet.
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                      <th style={{ padding: '10px 12px' }}>Timestamp</th>
                      <th style={{ padding: '10px 12px' }}>Action</th>
                      <th style={{ padding: '10px 12px' }}>Actor</th>
                      <th style={{ padding: '10px 12px' }}>Asset / Finding</th>
                      <th style={{ padding: '10px 12px' }}>Summary</th>
                      <th style={{ padding: '10px 12px' }}>Record Hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map(log => (
                      <tr key={log.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '10px 12px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                          {new Date(log.started_at).toLocaleTimeString()}
                        </td>
                        <td style={{ padding: '10px 12px', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                          {log.action}
                        </td>
                        <td style={{ padding: '10px 12px' }}>{log.actor}</td>
                        <td style={{ padding: '10px 12px', fontFamily: 'JetBrains Mono', fontSize: 11 }}>
                          {log.asset_id || log.finding_id || '-'}
                        </td>
                        <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                          {log.result_summary}
                        </td>
                        <td style={{ padding: '10px 12px', fontFamily: 'JetBrains Mono', fontSize: 10, color: 'var(--text-muted)' }}>
                          {log.record_hash ? `${log.record_hash.slice(0, 12)}...` : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MODAL: EVIDENCE & SHA-256 HASH */}
      {selectedEvidence && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: 20
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-bright)',
            borderRadius: 'var(--radius)',
            maxWidth: 750,
            width: '100%',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: 26
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Hash style={{ color: 'var(--accent-cyan)', width: 22, height: 22 }} />
                <h3 style={{ fontSize: 18, fontWeight: 800 }}>Technical Evidence & Hash Proof</h3>
              </div>
              <button
                onClick={() => setSelectedEvidence(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X style={{ width: 20, height: 20 }} />
              </button>
            </div>

            {selectedEvidence.evidence ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div style={{
                  background: selectedEvidence.integrity_verified ? 'rgba(52, 211, 153, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                  border: selectedEvidence.integrity_verified ? '1px solid rgba(52, 211, 153, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
                  padding: '10px 14px',
                  borderRadius: 8,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  fontSize: 13
                }}>
                  <CheckCircle style={{ color: 'var(--accent-green)', width: 16, height: 16 }} />
                  <span>
                    <strong>SHA-256 Tamper-Evident Integrity:</strong> {selectedEvidence.integrity_verified ? 'VERIFIED MATCH' : 'INTEGRITY MISMATCH'}
                  </span>
                </div>

                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }}>
                    SHA-256 Cryptographic Hash
                  </div>
                  <div style={{
                    background: 'var(--bg-elevated)',
                    padding: 10,
                    borderRadius: 6,
                    fontFamily: 'JetBrains Mono',
                    fontSize: 12,
                    color: 'var(--accent-cyan)'
                  }}>
                    {selectedEvidence.sha256_hash}
                  </div>
                </div>

                {selectedEvidence.evidence.request_sample && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }}>
                      Sanitized Request Sample
                    </div>
                    <pre style={{
                      background: 'var(--bg-elevated)',
                      padding: 12,
                      borderRadius: 6,
                      fontFamily: 'JetBrains Mono',
                      fontSize: 11,
                      overflowX: 'auto',
                      maxHeight: 180
                    }}>
                      {selectedEvidence.evidence.request_sample}
                    </pre>
                  </div>
                )}

                {selectedEvidence.evidence.response_sample && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }}>
                      Response Sample & Proof
                    </div>
                    <pre style={{
                      background: 'var(--bg-elevated)',
                      padding: 12,
                      borderRadius: 6,
                      fontFamily: 'JetBrains Mono',
                      fontSize: 11,
                      overflowX: 'auto',
                      maxHeight: 180
                    }}>
                      {selectedEvidence.evidence.response_sample}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', padding: 20 }}>No evidence captured yet.</div>
            )}
          </div>
        </div>
      )}

      {/* MODAL: EXPLAINABLE RISK BREAKDOWN */}
      {selectedRisk && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: 20
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-bright)',
            borderRadius: 'var(--radius)',
            maxWidth: 600,
            width: '100%',
            padding: 26
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ fontSize: 18, fontWeight: 800 }}>Explainable Contextual Cyber Risk</h3>
              <button
                onClick={() => setSelectedRisk(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X style={{ width: 20, height: 20 }} />
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
              <div style={{
                fontSize: 36,
                fontWeight: 900,
                color: selectedRisk.risk_tier === 'critical' ? 'var(--sev-critical)' : 'var(--sev-high)'
              }}>
                {selectedRisk.final_risk_score} <span style={{ fontSize: 16, color: 'var(--text-muted)' }}>/ 100</span>
              </div>
              <span className={`badge badge-${selectedRisk.risk_tier}`}>
                {selectedRisk.risk_tier.toUpperCase()} TIER
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
              {selectedRisk.explanation && Object.entries(selectedRisk.explanation).map(([key, val]) => (
                <div key={key} style={{
                  background: 'var(--bg-elevated)',
                  padding: '10px 14px',
                  borderRadius: 6,
                  display: 'flex',
                  justifyContent: 'space-between'
                }}>
                  <span style={{ color: 'var(--text-muted)', textTransform: 'capitalize' }}>{key.replace('_', ' ')}:</span>
                  <span style={{ fontWeight: 600 }}>{String(val)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MODAL: REMEDIATION PLAN */}
      {selectedRemediation && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: 20
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-bright)',
            borderRadius: 'var(--radius)',
            maxWidth: 650,
            width: '100%',
            padding: 26
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ fontSize: 18, fontWeight: 800 }}>Actionable Remediation Guidance</h3>
              <button
                onClick={() => setSelectedRemediation(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X style={{ width: 20, height: 20 }} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, fontSize: 13 }}>
              <div>
                <strong>Root Cause:</strong>
                <p style={{ color: 'var(--text-secondary)', marginTop: 4 }}>{selectedRemediation.root_cause}</p>
              </div>
              <div>
                <strong>Patch Recommendation:</strong>
                <p style={{ color: 'var(--accent-green)', marginTop: 4 }}>{selectedRemediation.patch_recommendation}</p>
              </div>
              <div>
                <strong>Configuration Directive:</strong>
                <p style={{ color: 'var(--accent-cyan)', marginTop: 4 }}>{selectedRemediation.config_recommendation}</p>
              </div>
              {selectedRemediation.mitigation_steps && (
                <div>
                  <strong>Mitigation Steps:</strong>
                  <ul style={{ paddingLeft: 20, marginTop: 4, color: 'var(--text-secondary)' }}>
                    {selectedRemediation.mitigation_steps.map((m: string, i: number) => (
                      <li key={i} style={{ marginBottom: 4 }}>{m}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* MODAL: REGISTER ASSET */}
      {showAuthModal && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: 20
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-bright)',
            borderRadius: 'var(--radius)',
            maxWidth: 550,
            width: '100%',
            padding: 26
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ fontSize: 18, fontWeight: 800 }}>Authorize Target Asset Scope</h3>
              <button
                onClick={() => setShowAuthModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X style={{ width: 20, height: 20 }} />
              </button>
            </div>

            <form onSubmit={handleCreateAuth} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>Hostname or IP Address *</label>
                <input
                  required
                  type="text"
                  placeholder="e.g. app.target.local or 192.168.1.100"
                  value={newAuth.hostname_or_ip}
                  onChange={e => setNewAuth({ ...newAuth, hostname_or_ip: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: '#fff',
                    marginTop: 4
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>Asset ID (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. asset-web-01"
                  value={newAuth.asset_id}
                  onChange={e => setNewAuth({ ...newAuth, asset_id: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: '#fff',
                    marginTop: 4
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>Asset Owner *</label>
                <input
                  required
                  type="text"
                  placeholder="e.g. AppSec Operations Team"
                  value={newAuth.owner}
                  onChange={e => setNewAuth({ ...newAuth, owner: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: '#fff',
                    marginTop: 4
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>Permitted Ports (Comma separated)</label>
                <input
                  type="text"
                  placeholder="80, 443, 8080"
                  value={newAuth.permitted_ports}
                  onChange={e => setNewAuth({ ...newAuth, permitted_ports: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: '#fff',
                    marginTop: 4
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: 10, marginTop: 10 }}>
                <button
                  type="submit"
                  style={{
                    flex: 1,
                    background: 'var(--primary)',
                    color: '#fff',
                    border: 'none',
                    padding: 10,
                    borderRadius: 6,
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  Save Authorization Record
                </button>
                <button
                  type="button"
                  onClick={() => setShowAuthModal(false)}
                  style={{
                    background: 'var(--bg-elevated)',
                    color: 'var(--text-muted)',
                    border: '1px solid var(--border)',
                    padding: '10px 16px',
                    borderRadius: 6,
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
