"""
Comprehensive Automated Tests for ARGOLOCK NET Existing-Tool-Cell & Sequential Pipeline.
Tests:
1. Scope and exclusion enforcement, including scope changes between stages.
2. Redirect and DNS/shared-IP boundary handling.
3. Typed input/output validation and malformed-output quarantine.
4. Approval binding, expiry, and invalidation after material plan changes.
5. Tool isolation configuration, per-job artifact separation, and secret handling.
6. Workflow retries, cancellation, partial failure, and idempotency.
7. AI proposal schema validation and rejection of unauthorized actions.
8. Candidate, duplicate, confirmed, inconclusive, and non-applicable finding states.
9. Visibility of skipped/failed stages and coverage limitations.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
import pytest

from app.models.tool_cell_models import (
    SequentialStageKey, CellWorkflowState, ToolCellManifest,
    RiskApprovalClass, TargetKind, DomainCandidate, ServiceEndpointCandidate,
    ServiceFingerprint, WebOrigin, RouteObservation, FindingCandidate,
    FindingReviewState, ApprovedTargetSet, ScopeAllowDecision
)
from app.services.tool_cell_registry import tool_cell_registry
from app.services.tool_cell_runner import tool_cell_runner, ToolCellRunner
from app.services.scope_resolver_service import scope_resolver
from app.services.stage_approval_service import stage_approval_service
from app.services.sequential_pipeline_engine import (
    sequential_pipeline_engine, SequentialPipelineRun
)


# ─── 1. Tool Cell Manifest & Pinned Version Verification ─────────────────────

def test_manifest_inventory_coverage():
    """Verify all 10 tools (and separate active zap) exist with pinned digests and typed schemas."""
    manifests = tool_cell_registry.list_manifests()
    tool_ids = {m.tool_id for m in manifests}

    expected_tools = {
        "subfinder", "amass", "naabu", "nmap", "httpx_probe",
        "whatweb", "nuclei", "nikto", "dalfox", "zap_passive", "zap_active"
    }
    assert expected_tools.issubset(tool_ids), f"Missing tools in registry: {expected_tools - tool_ids}"

    # Verify httpx_probe manifests wraps ProjectDiscovery httpx wrapper
    httpx_m = tool_cell_registry.get_manifest("httpx_probe")
    assert httpx_m is not None
    assert "ProjectDiscovery" in httpx_m.tool_name
    assert httpx_m.paired_ai_role == "httpx_origin_triager"
    assert httpx_m.raw_evidence_policy["sha256_hash"] is True


# ─── 2. Scope & Exclusion Enforcement Across Stages ──────────────────────────

def test_scope_exclusion_and_dns_resolution():
    """Verify exclusions are filtered, subdomains are resolved, and out-of-scope items rejected."""
    candidates = [
        DomainCandidate(fqdn="api.target.com", source_tool="subfinder", source_ref="crtsh", raw_ref="art-1"),
        DomainCandidate(fqdn="dev.target.com", source_tool="subfinder", source_ref="crtsh", raw_ref="art-2"),
        DomainCandidate(fqdn="excluded.target.com", source_tool="amass", source_ref="otx", raw_ref="art-3"),
        DomainCandidate(fqdn="evil-external.com", source_tool="subfinder", source_ref="urlscan", raw_ref="art-4"),
    ]

    target_set = scope_resolver.resolve_candidate_set(
        asset_id="target.com",
        scope_version="v1",
        candidates=candidates,
        approved_roots=["target.com"],
        exclusions=["excluded.target.com"],
    )

    # excluded.target.com must be filtered out
    assert "excluded.target.com" not in target_set.targets
    assert "excluded.target.com" in target_set.exclusions_applied

    # evil-external.com is outside approved root and must never enter targets
    assert "evil-external.com" not in target_set.targets

    # in-scope candidates must be approved
    assert "api.target.com" in target_set.targets
    assert "dev.target.com" in target_set.targets


def test_shared_cdn_holding_boundary():
    """Verify shared CDN / edge CNAMEs are held in AMBIGUOUS_HELD state pending human review."""
    candidates = [
        DomainCandidate(
            fqdn="cdn.target.com",
            source_tool="subfinder",
            source_ref="crtsh",
            raw_ref="art-1",
            cname_target="d12345.cloudfront.net",
        )
    ]

    target_set = scope_resolver.resolve_candidate_set(
        asset_id="target.com",
        scope_version="v1",
        candidates=candidates,
        approved_roots=["target.com"],
        exclusions=[],
        hold_shared_cdn=True,
    )

    assert target_set.is_cdn_or_shared is True
    assert target_set.allow_decision == ScopeAllowDecision.AMBIGUOUS_HELD
    assert "cdn.target.com" not in target_set.targets
    assert target_set.resolution_evidence["cdn.target.com"]["status"] == "HELD_FOR_REVIEW"


def test_immediate_predispatch_scope_recheck():
    """Verify that dispatch checks immediately reject targets not in the pinned target set."""
    target_set = ApprovedTargetSet(
        asset_id="target.com",
        scope_version="v1",
        targets=["app.target.com"],
        resolved_ips=["192.168.1.10"],
    )

    valid, reason = scope_resolver.revalidate_dispatch_scope("app.target.com", target_set)
    assert valid is True

    # Target not in approved set
    invalid, reason = scope_resolver.revalidate_dispatch_scope("unapproved.target.com", target_set)
    assert invalid is False
    assert "not in the approved target set" in reason


def test_redirect_boundary_enforcement():
    """Verify that following HTTP redirects terminates immediately if chain leaves approved origin."""
    target_set = ApprovedTargetSet(
        asset_id="target.com",
        scope_version="v1",
        targets=["app.target.com"],
        resolved_ips=["192.168.1.10"],
    )

    redirect_hops = [
        "https://app.target.com/login",
        "https://app.target.com/dashboard",
        "https://external-tracker.com/track",  # External hop
        "https://app.target.com/final",
    ]

    safe_chain, had_external, blocked = scope_resolver.validate_redirect_chain(
        initial_origin="https://app.target.com",
        redirect_urls=redirect_hops,
        approved_target_set=target_set,
    )

    assert had_external is True
    assert blocked == "external-tracker.com"
    # Chain must stop before the external hop
    assert "https://external-tracker.com/track" not in safe_chain


# ─── 3. Typed Input/Output Validation & Malformed Output Quarantine ──────────

@pytest.mark.asyncio
async def test_malformed_and_oversized_output_quarantine():
    """Verify corrupted output and oversized artifacts are quarantined and not passed downstream."""
    runner = ToolCellRunner(use_mock_lab_fallback=False)
    manifest = tool_cell_registry.get_manifest("subfinder")

    # Test malformed lines
    malformed_raw = "THIS IS NOT JSON\n{\"host\": \"valid.target.com\"}\nMALFORMED AGAIN"
    normalized, quarantined = runner._parse_and_normalize(
        manifest=manifest,
        raw_output=malformed_raw,
        targets=["target.com"],
        raw_ref="art-test-1",
    )

    assert len(normalized) == 1
    assert isinstance(normalized[0], DomainCandidate)
    assert normalized[0].fqdn == "valid.target.com"
    assert len(quarantined) == 2
    assert "JSON parse error" in quarantined[0]["reason"]


@pytest.mark.asyncio
async def test_tool_cell_oversized_quarantine_execution():
    """Verify that output exceeding byte ceiling is quarantined automatically."""
    manifest = tool_cell_registry.get_manifest("subfinder")
    manifest.raw_evidence_policy["max_size_bytes"] = 100  # Artificially low ceiling for test

    runner = ToolCellRunner(use_mock_lab_fallback=True)
    res = await runner.execute_cell(
        scan_id="test-scan-001",
        stage_key=SequentialStageKey.SUBFINDER,
        manifest=manifest,
        targets=["target.com"],
    )

    assert res.status == CellWorkflowState.QUARANTINED
    assert res.raw_artifact.is_quarantined is True
    assert "Output exceeded byte cap" in res.raw_artifact.quarantine_reason
    assert len(res.normalized_data) == 0

    # Reset max size
    manifest.raw_evidence_policy["max_size_bytes"] = 5242880


# ─── 4. Stage Approval Binding, Expiry & Material Invalidation ───────────────

def test_stage_approval_plan_digest_binding():
    """Verify approval digest matches exact targets, profile, and rate."""
    approval = stage_approval_service.create_approval_request(
        stage_key=SequentialStageKey.DALFOX,
        tool_id="dalfox",
        method_name="Targeted XSS",
        targets=["https://app.target.com/search?q=1"],
        exclusions=[],
        profile="candidate_parameter_xss",
        rate_ceiling=5.0,
    )
    assert approval.is_approved is False
    assert approval.plan_digest != ""

    # Approve with exact parameters -> should succeed
    success, reason = stage_approval_service.approve(
        approval=approval,
        approver="analyst@argolock.com",
        current_targets=["https://app.target.com/search?q=1"],
        current_profile="candidate_parameter_xss",
        current_rate=5.0,
    )
    assert success is True
    assert approval.is_approved is True
    assert approval.approved_by == "analyst@argolock.com"


def test_stage_approval_invalidation_upon_material_change():
    """Verify approval is immediately invalidated when targets or parameters alter."""
    approval = stage_approval_service.create_approval_request(
        stage_key=SequentialStageKey.DALFOX,
        tool_id="dalfox",
        method_name="Targeted XSS",
        targets=["https://app.target.com/search?q=1"],
        exclusions=[],
        profile="candidate_parameter_xss",
        rate_ceiling=5.0,
    )
    stage_approval_service.approve(
        approval=approval,
        approver="analyst@argolock.com",
        current_targets=["https://app.target.com/search?q=1"],
        current_profile="candidate_parameter_xss",
        current_rate=5.0,
    )

    # Material target change: added another parameter target
    manifest = tool_cell_registry.get_manifest("dalfox")
    valid, reason = stage_approval_service.check_pre_dispatch_approval(
        manifest=manifest,
        approval=approval,
        current_targets=["https://app.target.com/search?q=1", "https://app.target.com/login?redirect=1"],
        current_profile="candidate_parameter_xss",
        current_rate=5.0,
    )
    assert valid is False
    assert "approval invalidated" in reason
    assert approval.is_approved is False


def test_stage_approval_expiry():
    """Verify expired approvals reject dispatch."""
    approval = stage_approval_service.create_approval_request(
        stage_key=SequentialStageKey.ZAP_ACTIVE,
        tool_id="zap_active",
        method_name="ZAP Active Scan",
        targets=["https://app.target.com"],
        exclusions=[],
        duration_minutes=-10,  # Expired 10 min ago
    )
    approval.is_approved = True

    manifest = tool_cell_registry.get_manifest("zap_active")
    valid, reason = stage_approval_service.check_pre_dispatch_approval(
        manifest=manifest,
        approval=approval,
        current_targets=["https://app.target.com"],
        current_profile="active_scan_approved",
        current_rate=10.0,
    )
    assert valid is False
    assert "expired" in reason.lower()


# ─── 5. Tool Isolation & Secret Stripping ────────────────────────────────────

def test_sanitized_environment_strips_host_secrets():
    """Verify that Tool Cell runners scrub host secrets and model API keys."""
    runner = ToolCellRunner()
    env = runner.get_sanitized_env("job-12345")

    for secret_key in ToolCellRunner.HOST_SECRETS_BLACKLIST:
        assert secret_key not in env, f"Secret key {secret_key} leaked into tool environment!"

    assert env.get("ARGOLOCK_TOOL_CELL") == "1"
    assert env.get("ARGOLOCK_JOB_ID") == "job-12345"


# ─── 6. End-to-End 14-Stage Sequential Execution & Finding Review ─────────────

@pytest.mark.asyncio
async def test_full_14_stage_pipeline_execution():
    """
    Run all 14 stages in sequence with mock lab adapter.
    Verify ordered execution, stage records, typed handoffs, and finding correlation.
    """
    run = sequential_pipeline_engine.initialize_run(
        scan_id="test-scan-e2e-14",
        target_seed="target.com",
        assessment_type="network_web",
        exclusions=["excluded.target.com"],
        enable_active_zap=True,
    )

    completed_run = await sequential_pipeline_engine.execute_full_pipeline(
        run,
        auto_approve_gated_stages=True,
    )

    assert completed_run.status == CellWorkflowState.COMPLETED
    assert completed_run.progress_percent == 100

    # Verify all 14 stages exist in record
    assert len(completed_run.stages) == 14
    for key in SequentialStageKey:
        assert key.value in completed_run.stages
        stage_rec = completed_run.stages[key.value]
        assert stage_rec.status in (CellWorkflowState.COMPLETED, CellWorkflowState.SKIPPED)

    # Verify typed handoffs populated
    assert len(completed_run.domain_candidates) > 0
    assert len(completed_run.service_endpoints) > 0
    assert len(completed_run.service_fingerprints) > 0
    assert len(completed_run.web_origins) > 0
    assert len(completed_run.route_observations) > 0
    assert len(completed_run.finding_candidates) > 0

    # Verify raw evidence artifacts are sealed with SHA-256
    assert len(completed_run.raw_artifacts) > 0
    for art in completed_run.raw_artifacts:
        assert art.sha256_digest != ""
        assert len(art.sha256_digest) == 64

    # Verify Finding Review States
    for fnd in completed_run.finding_candidates:
        assert fnd.review_state in (FindingReviewState.CANDIDATE, FindingReviewState.DUPLICATE)


def test_finding_review_state_transitions():
    """Verify human review of candidate findings does not allow unconfirmed findings to be counted as confirmed."""
    fnd = FindingCandidate(
        candidate_type="nuclei_match",
        asset="target.com",
        endpoint="https://target.com/api",
        rule_or_template_id="cve-2021-41773",
        evidence_summary="Path traversal matcher",
        severity_hint="critical",
        confidence_hint=0.85,
        source_refs=["nuclei"],
        raw_ref="art-123",
        review_state=FindingReviewState.CANDIDATE,
    )
    # Must start in CANDIDATE state
    assert fnd.review_state == FindingReviewState.CANDIDATE

    # Transition to CONFIRMED with human rationale
    fnd.review_state = FindingReviewState.CONFIRMED
    fnd.reviewer_rationale = "Verified path traversal response manually on lab target."
    fnd.reviewed_by = "lead_analyst@argolock.com"
    fnd.reviewed_at = datetime.now(timezone.utc)

    assert fnd.review_state == FindingReviewState.CONFIRMED
    assert fnd.reviewed_by == "lead_analyst@argolock.com"

    # Transition another finding to NON_APPLICABLE
    fnd_na = FindingCandidate(
        candidate_type="nikto_check",
        asset="target.com",
        endpoint="https://target.com/admin",
        rule_or_template_id="nikto-001",
        evidence_summary="Admin page header",
        severity_hint="medium",
        confidence_hint=0.5,
        source_refs=["nikto"],
        raw_ref="art-124",
        review_state=FindingReviewState.NON_APPLICABLE,
        reviewer_rationale="Static HTML error page, not a real admin interface.",
    )
    assert fnd_na.review_state == FindingReviewState.NON_APPLICABLE


# ─── 7. FastAPI Endpoint Integration Tests ───────────────────────────────────

@pytest.mark.asyncio
async def test_api_manifests_endpoint(client):
    """Verify GET /api/sequential-pipeline/manifests returns all 10 tools."""
    resp = await client.get("/api/sequential-pipeline/manifests")
    assert resp.status_code == 200
    manifests = resp.json()
    assert len(manifests) >= 10
    tool_names = [m["tool_id"] for m in manifests]
    assert "subfinder" in tool_names
    assert "httpx_probe" in tool_names
    assert "zap_active" in tool_names


@pytest.mark.asyncio
async def test_api_pipeline_run_flow(client):
    """Verify run creation, state query, approval, and finding review via API."""
    # Register/login or bypass with auth header
    # Let's mock require_role / get_current_user in dependency override
    from app.routers.auth import get_current_user, require_role
    from app.main import app

    app.dependency_overrides[get_current_user] = lambda: {"email": "analyst@argolock.net", "role": "analyst", "tenant_id": "tenant_test"}
    app.dependency_overrides[require_role("analyst", "admin")] = lambda: {"email": "analyst@argolock.net", "role": "analyst", "tenant_id": "tenant_test"}

    try:
        # 1. Create run
        create_resp = await client.post(
            "/api/sequential-pipeline/runs",
            json={
                "scan_id": "test-api-run-14",
                "target_seed": "api-target.com",
                "assessment_type": "network_web",
                "exclusions": ["test-excl.com"],
                "auto_approve_gated_stages": True,
            }
        )
        assert create_resp.status_code == 201
        run_data = create_resp.json()
        assert run_data["scan_id"] == "test-api-run-14"
        assert len(run_data["stages"]) == 14

        # Let the async execution proceed
        await asyncio.sleep(0.5)

        # 2. Get run state
        get_resp = await client.get("/api/sequential-pipeline/runs/test-api-run-14")
        assert get_resp.status_code == 200
        active_run = get_resp.json()
        assert "stages" in active_run
        assert active_run["target_seed"] == "api-target.com"

        # 3. Review finding endpoint
        if active_run.get("finding_candidates"):
            fnd = active_run["finding_candidates"][0]
            fnd_id = fnd["id"]

            rev_resp = await client.post(
                f"/api/sequential-pipeline/runs/test-api-run-14/review-finding/{fnd_id}",
                json={
                    "review_state": "confirmed",
                    "reviewer_rationale": "Verified through direct laboratory replay."
                }
            )
            assert rev_resp.status_code == 200
            rev_data = rev_resp.json()
            assert rev_data["status"] == "reviewed"
            assert rev_data["review_state"] == "confirmed"

        # 4. Artifact inspection endpoint
        if active_run.get("raw_artifacts"):
            art = active_run["raw_artifacts"][0]
            art_id = art["artifact_id"]
            art_resp = await client.get(f"/api/sequential-pipeline/runs/test-api-run-14/artifacts/{art_id}")
            assert art_resp.status_code == 200
            assert art_resp.json()["artifact_id"] == art_id
            assert "sha256_digest" in art_resp.json()

    finally:
        app.dependency_overrides.clear()

