import React, { useState } from 'react';
import {
  SequentialPipelineRun, SequentialStageRecord, FindingCandidateRecord,
  StageApproval, ToolCellManifest, api
} from '../lib/api';
import {
  Shield, CheckCircle2, Clock, AlertTriangle, XCircle, PauseCircle,
  FileText, ArrowRight, Lock, Eye, Check, AlertCircle, RefreshCw, Layers
} from 'lucide-react';

interface SequentialPipelineCanvasProps {
  run: SequentialPipelineRun | null;
  onRefresh: () => void;
  manifests?: ToolCellManifest[];
}

export function SequentialPipelineCanvas({ run, onRefresh, manifests = [] }: SequentialPipelineCanvasProps) {
  const [selectedStage, setSelectedStage] = useState<SequentialStageRecord | null>(null);
  const [reviewingFinding, setReviewingFinding] = useState<FindingCandidateRecord | null>(null);
  const [reviewerRationale, setReviewerRationale] = useState('');
  const [selectedReviewState, setSelectedReviewState] = useState<string>('confirmed');
  const [submittingReview, setSubmittingReview] = useState(false);
  const [approvalNotes, setApprovalNotes] = useState('');
  const [submittingApproval, setSubmittingApproval] = useState(false);
  const [findingFilter, setFindingFilter] = useState<string>('all');
  const [inspectedArtifact, setInspectedArtifact] = useState<any | null>(null);
  const [loadingArtifact, setLoadingArtifact] = useState(false);

  if (!run) {
    return (
      <div className="card" style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
        <Layers style={{ width: 48, height: 48, margin: '0 auto 16px', opacity: 0.5 }} />
        <p>No sequential tool pipeline execution found for this assessment.</p>
      </div>
    );
  }

  const stagesList = Object.values(run.stages || {}).sort((a, b) => a.stage_key.localeCompare(b.stage_key));

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <span className="badge badge-success" style={{ display: 'flex', alignItems: 'center', gap: 4 }}><CheckCircle2 style={{ width: 12, height: 12 }} /> COMPLETED</span>;
      case 'RUNNING':
        return <span className="badge badge-info" style={{ display: 'flex', alignItems: 'center', gap: 4 }}><RefreshCw className="animate-spin" style={{ width: 12, height: 12 }} /> RUNNING</span>;
      case 'APPROVAL_REQUIRED':
        return <span className="badge badge-warning" style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'rgba(245, 158, 11, 0.2)', color: '#f59e0b', border: '1px solid #f59e0b' }}><Lock style={{ width: 12, height: 12 }} /> APPROVAL REQUIRED</span>;
      case 'SKIPPED':
        return <span className="badge badge-secondary" style={{ display: 'flex', alignItems: 'center', gap: 4 }}><PauseCircle style={{ width: 12, height: 12 }} /> SKIPPED</span>;
      case 'QUARANTINED':
        return <span className="badge badge-danger" style={{ display: 'flex', alignItems: 'center', gap: 4 }}><AlertTriangle style={{ width: 12, height: 12 }} /> QUARANTINED</span>;
      case 'FAILED':
        return <span className="badge badge-danger" style={{ display: 'flex', alignItems: 'center', gap: 4 }}><XCircle style={{ width: 12, height: 12 }} /> FAILED</span>;
      case 'PARTIAL':
        return <span className="badge badge-warning" style={{ display: 'flex', alignItems: 'center', gap: 4 }}><AlertCircle style={{ width: 12, height: 12 }} /> PARTIAL</span>;
      default:
        return <span className="badge badge-outline" style={{ display: 'flex', alignItems: 'center', gap: 4 }}><Clock style={{ width: 12, height: 12 }} /> {status || 'PLANNED'}</span>;
    }
  };

  const handleApproveStage = async (approvalId: string) => {
    setSubmittingApproval(true);
    try {
      await api.sequentialPipeline.approveStage(run.scan_id, approvalId, approvalNotes);
      setApprovalNotes('');
      onRefresh();
    } catch (err: any) {
      alert(`Approval failed: ${err.message || String(err)}`);
    } finally {
      setSubmittingApproval(false);
    }
  };

  const handleReviewFinding = async () => {
    if (!reviewingFinding) return;
    if (!reviewerRationale.trim()) {
      alert('Reviewer rationale is mandatory to record human accountability.');
      return;
    }
    setSubmittingReview(true);
    try {
      await api.sequentialPipeline.reviewFinding(
        run.scan_id,
        reviewingFinding.id,
        selectedReviewState,
        reviewerRationale
      );
      setReviewingFinding(null);
      setReviewerRationale('');
      onRefresh();
    } catch (err: any) {
      alert(`Review failed: ${err.message || String(err)}`);
    } finally {
      setSubmittingReview(false);
    }
  };

  const handleInspectArtifact = async (artifactId: string) => {
    setLoadingArtifact(true);
    try {
      const art = await api.sequentialPipeline.getArtifact(run.scan_id, artifactId);
      setInspectedArtifact(art);
    } catch (err: any) {
      alert(`Failed to fetch artifact: ${err.message || String(err)}`);
    } finally {
      setLoadingArtifact(false);
    }
  };

  const pendingApprovals = Object.values(run.approvals || {}).filter(a => !a.is_approved);

  const filteredFindings = (run.finding_candidates || []).filter(f => {
    if (findingFilter === 'all') return true;
    return f.review_state === findingFilter;
  });

  const confirmedCount = (run.finding_candidates || []).filter(f => f.review_state === 'confirmed').length;
  const candidateCount = (run.finding_candidates || []).filter(f => f.review_state === 'candidate').length;
  const duplicateCount = (run.finding_candidates || []).filter(f => f.review_state === 'duplicate').length;
  const nonApplicableCount = (run.finding_candidates || []).filter(f => f.review_state === 'non_applicable' || f.review_state === 'inconclusive').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ── 1. API Coverage Limitation Banner ── */}
      <div style={{
        background: 'rgba(59, 130, 246, 0.08)',
        border: '1px solid rgba(59, 130, 246, 0.3)',
        borderRadius: 8,
        padding: '14px 18px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12,
      }}>
        <AlertCircle style={{ width: 20, height: 20, color: '#3b82f6', flexShrink: 0, marginTop: 2 }} />
        <div style={{ fontSize: '13px', lineHeight: 1.5 }}>
          <strong style={{ color: 'var(--text-primary)' }}>Phase 1 Tool Inventory Scope & Coverage Notice:</strong>{' '}
          <span style={{ color: 'var(--text-secondary)' }}>
            The 10-tool inventory directly covers Network and Web Application assessments. Dedicated API schema-aware fuzzing and testing has an identified capability gap awaiting tool selection.
          </span>
        </div>
      </div>

      {/* ── 2. Scope & Target Set Summary ── */}
      {run.approved_target_set && (
        <div className="card" style={{ padding: 18, background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield style={{ width: 18, height: 18, color: 'var(--accent-cyan)' }} />
              <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>
                Scope Resolution Boundary ({run.approved_target_set.scope_version})
              </h3>
            </div>
            {run.approved_target_set.is_cdn_or_shared && (
              <span className="badge badge-warning" style={{ fontSize: '11px' }}>
                Shared CDN / Cloud Edge Detected ({run.approved_target_set.shared_provider || 'Held'})
              </span>
            )}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, fontSize: '12px', color: 'var(--text-secondary)' }}>
            <div><strong>Approved Targets:</strong> {run.approved_target_set.targets.length} host(s)</div>
            <div><strong>Resolved IPs:</strong> {run.approved_target_set.resolved_ips.length} IP(s)</div>
            <div><strong>Exclusions Applied:</strong> {run.approved_target_set.exclusions_applied.length} rule(s)</div>
            <div><strong>Boundary Decision:</strong> <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>{run.approved_target_set.allow_decision}</span></div>
          </div>
        </div>
      )}

      {/* ── 3. Pending Stage Approvals (Gated Stages) ── */}
      {pendingApprovals.length > 0 && (
        <div style={{
          background: 'rgba(245, 158, 11, 0.08)',
          border: '1px solid rgba(245, 158, 11, 0.4)',
          borderRadius: 8,
          padding: 20,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <Lock style={{ width: 20, height: 20, color: '#f59e0b' }} />
            <h4 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#f59e0b' }}>
              Action Required: Operator Testing Approval Required
            </h4>
          </div>
          {pendingApprovals.map(appr => (
            <div key={appr.approval_id} style={{ background: 'rgba(0,0,0,0.2)', padding: 16, borderRadius: 6, marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{appr.method_name} ({appr.tool_id})</span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Class: {appr.expected_traffic_class}</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
                Target Count: <strong>{appr.target_count}</strong> | Rate Ceiling: <strong>{appr.rate_ceiling} req/s</strong> | Timeout: <strong>{appr.timeout_seconds}s</strong>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <input
                  type="text"
                  placeholder="Operator approval decision notes..."
                  value={approvalNotes}
                  onChange={e => setApprovalNotes(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '6px 10px',
                    fontSize: '12px',
                    color: 'var(--text-primary)',
                  }}
                />
                <button
                  className="btn btn-primary"
                  style={{ fontSize: '12px', padding: '6px 14px' }}
                  onClick={() => handleApproveStage(appr.approval_id)}
                  disabled={submittingApproval}
                >
                  <Check style={{ width: 14, height: 14, marginRight: 4 }} />
                  {submittingApproval ? 'Signing...' : 'Approve Stage'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── 4. Sequential 14-Stage Canvas ── */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Sequential Tool Pipeline (14 Stages)</h3>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Progress: {run.progress_percent}%</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {stagesList.map((stage, idx) => (
            <div
              key={stage.stage_key}
              onClick={() => setSelectedStage(stage)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 16px',
                background: selectedStage?.stage_key === stage.stage_key ? 'rgba(99, 102, 241, 0.12)' : 'rgba(255,255,255,0.02)',
                border: selectedStage?.stage_key === stage.stage_key ? '1px solid var(--primary-light)' : '1px solid var(--border)',
                borderRadius: 6,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: 'var(--text-muted)', width: 24 }}>
                  {String(idx + 1).padStart(2, '0')}
                </span>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {stage.stage_name}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Tool: <span style={{ color: 'var(--primary-light)' }}>{stage.tool_id}</span> ({stage.profile_used})
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {stage.normalized_count > 0 && <span>Normalized: {stage.normalized_count}</span>}
                  {stage.quarantined_count > 0 && <span style={{ color: 'var(--sev-critical)', marginLeft: 8 }}>Quarantined: {stage.quarantined_count}</span>}
                </div>
                {getStatusBadge(stage.status)}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── 5. Stage Handoff & Evidence Drawer ── */}
      {selectedStage && (
        <div className="card" style={{ padding: 20, border: '1px solid var(--primary-light)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h4 style={{ margin: 0, fontSize: 15, fontWeight: 700 }}>
              Stage Handoff Detail: {selectedStage.stage_name}
            </h4>
            <button className="btn btn-outline" style={{ fontSize: '11px', padding: '4px 8px' }} onClick={() => setSelectedStage(null)}>
              Close
            </button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, fontSize: '12px', marginBottom: 16 }}>
            <div><strong>Status:</strong> {selectedStage.status}</div>
            <div><strong>Duration:</strong> {selectedStage.duration_seconds ? `${selectedStage.duration_seconds}s` : 'N/A'}</div>
            <div><strong>Targets:</strong> {selectedStage.target_count}</div>
            <div><strong>Normalized Records:</strong> {selectedStage.normalized_count}</div>
            <div><strong>Quarantined Records:</strong> {selectedStage.quarantined_count}</div>
            <div>
              <strong>Raw Evidence:</strong>{' '}
              {selectedStage.raw_artifact_ref ? (
                <button
                  className="btn btn-outline"
                  style={{ fontSize: '10px', padding: '2px 6px', marginLeft: 4 }}
                  onClick={() => handleInspectArtifact(selectedStage.raw_artifact_ref!)}
                >
                  <Eye style={{ width: 10, height: 10, marginRight: 2 }} />
                  Inspect Artifact
                </button>
              ) : 'None'}
            </div>
          </div>
          {selectedStage.coverage_notes && (
            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px 14px', borderRadius: 6, fontSize: '12px', color: 'var(--text-secondary)' }}>
              <strong>Coverage Notes:</strong> {selectedStage.coverage_notes}
            </div>
          )}
        </div>
      )}

      {/* ── 6. Immutable Artifact Inspector Modal ── */}
      {inspectedArtifact && (
        <div className="modal-backdrop" style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="card" style={{ width: 700, maxHeight: '80vh', overflowY: 'auto', padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>
                Immutable Raw Evidence: {inspectedArtifact.artifact_id}
              </h3>
              <button className="btn btn-outline" onClick={() => setInspectedArtifact(null)}>Close</button>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: 12, wordBreak: 'break-all' }}>
              SHA-256 Digest: <span style={{ color: 'var(--accent-cyan)' }}>{inspectedArtifact.sha256_digest}</span>
            </div>
            <pre style={{
              background: '#0a0d14', padding: 16, borderRadius: 6, fontSize: '11px',
              fontFamily: 'JetBrains Mono, monospace', overflowX: 'auto', maxHeight: 350
            }}>
              {inspectedArtifact.raw_content}
            </pre>
          </div>
        </div>
      )}

      {/* ── 7. Evidence-Backed Finding Review Center ── */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Evidence-Backed Finding Review</h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '4px 0 0' }}>
              Human accountability gate. Unconfirmed scanner hypotheses do not inflate confirmed counts.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className={`btn ${findingFilter === 'all' ? 'btn-primary' : 'btn-outline'}`} style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => setFindingFilter('all')}>
              All ({run.finding_candidates.length})
            </button>
            <button className={`btn ${findingFilter === 'confirmed' ? 'btn-primary' : 'btn-outline'}`} style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => setFindingFilter('confirmed')}>
              Confirmed ({confirmedCount})
            </button>
            <button className={`btn ${findingFilter === 'candidate' ? 'btn-primary' : 'btn-outline'}`} style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => setFindingFilter('candidate')}>
              Candidate ({candidateCount})
            </button>
            <button className={`btn ${findingFilter === 'duplicate' ? 'btn-primary' : 'btn-outline'}`} style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => setFindingFilter('duplicate')}>
              Duplicate ({duplicateCount})
            </button>
            <button className={`btn ${findingFilter === 'non_applicable' ? 'btn-primary' : 'btn-outline'}`} style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => setFindingFilter('non_applicable')}>
              Inconclusive/N.A. ({nonApplicableCount})
            </button>
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
            No findings matching filter '{findingFilter}'.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {filteredFindings.map(f => (
              <div
                key={f.id}
                style={{
                  padding: '12px 16px',
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {f.rule_or_template_id}
                    </span>
                    <span className="badge badge-outline" style={{ fontSize: '10px' }}>{f.candidate_type}</span>
                    <span className="badge" style={{
                      fontSize: '10px',
                      background: f.review_state === 'confirmed' ? 'rgba(34, 197, 94, 0.2)' : f.review_state === 'duplicate' ? 'rgba(156, 163, 175, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                      color: f.review_state === 'confirmed' ? '#22c55e' : f.review_state === 'duplicate' ? '#9ca3af' : '#f59e0b',
                    }}>
                      {f.review_state.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Endpoint: <span style={{ color: 'var(--accent-cyan)' }}>{f.endpoint}</span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 2 }}>
                    Evidence: {f.evidence_summary}
                  </div>
                  {f.reviewer_rationale && (
                    <div style={{ fontSize: '11px', color: 'var(--primary-light)', marginTop: 4 }}>
                      Reviewer Rationale ({f.reviewed_by}): {f.reviewer_rationale}
                    </div>
                  )}
                </div>

                <button
                  className="btn btn-outline"
                  style={{ fontSize: '11px', padding: '4px 10px' }}
                  onClick={() => {
                    setReviewingFinding(f);
                    setSelectedReviewState(f.review_state);
                    setReviewerRationale(f.reviewer_rationale || '');
                  }}
                >
                  Review Decision
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── 8. Finding Review Decision Drawer ── */}
      {reviewingFinding && (
        <div className="card" style={{ padding: 20, border: '1px solid var(--accent-cyan)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h4 style={{ margin: 0, fontSize: 15, fontWeight: 700 }}>
              Analyst Review Decision: {reviewingFinding.rule_or_template_id}
            </h4>
            <button className="btn btn-outline" style={{ fontSize: '11px', padding: '4px 8px' }} onClick={() => setReviewingFinding(null)}>
              Cancel
            </button>
          </div>
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: '12px', fontWeight: 600, display: 'block', marginBottom: 6 }}>
              Target State:
            </label>
            <div style={{ display: 'flex', gap: 10 }}>
              {['confirmed', 'duplicate', 'inconclusive', 'non_applicable'].map(st => (
                <button
                  key={st}
                  className={`btn ${selectedReviewState === st ? 'btn-primary' : 'btn-outline'}`}
                  style={{ fontSize: '11px', padding: '4px 12px' }}
                  onClick={() => setSelectedReviewState(st)}
                >
                  {st.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: '12px', fontWeight: 600, display: 'block', marginBottom: 6 }}>
              Reviewer Rationale (Mandatory):
            </label>
            <textarea
              rows={3}
              value={reviewerRationale}
              onChange={e => setReviewerRationale(e.target.value)}
              placeholder="Provide evidence-backed rationale for this finding confirmation or dismissal..."
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                padding: '8px 10px',
                fontSize: '12px',
                color: 'var(--text-primary)',
              }}
            />
          </div>
          <button
            className="btn btn-primary"
            style={{ fontSize: '12px', padding: '6px 14px' }}
            onClick={handleReviewFinding}
            disabled={submittingReview}
          >
            {submittingReview ? 'Submitting...' : 'Confirm Review State'}
          </button>
        </div>
      )}
    </div>
  );
}
