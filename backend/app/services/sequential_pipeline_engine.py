"""
ARGOLOCK NET Sequential Pipeline Orchestrator (14 Stages).
Complies with ARGOLOCK_NET_Phase1_Existing_Tool_Cells_and_Sequential_Pipeline_v1.0.md.

Orchestrates:
1. Preflight
2. Subfinder passive discovery
3. Amass passive enrichment
4. Scope resolution & boundary approval gate
5. Naabu bounded port discovery
6. Nmap focused service/version probes
7. httpx_probe approved HTTP(S) probing
8. WhatWeb conservative technology fingerprinting
9. Nuclei curated network & web template checks
10. ZAP crawl & passive review
11. Conditional Nikto server checks
12. Conditional Dalfox parameter checks (gated)
13. Separately approved ZAP active scan (gated)
14. Evidence correlation, deduplication, and human review preparation
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger
from pydantic import BaseModel, Field

from app.models.tool_cell_models import (
    SequentialStageKey, CellWorkflowState, StageExecutionRecord,
    StageApproval, ApprovedTargetSet, DomainCandidate, ServiceEndpointCandidate,
    ServiceFingerprint, WebOrigin, RouteObservation, FindingCandidate,
    FindingReviewState, RawEvidenceArtifact, AIPairedProposal
)
from app.services.tool_cell_registry import tool_cell_registry
from app.services.tool_cell_runner import tool_cell_runner
from app.services.scope_resolver_service import scope_resolver
from app.services.stage_approval_service import stage_approval_service


class SequentialPipelineRun(BaseModel):
    """Execution state document for the 14-stage assessment pipeline."""
    scan_id: str
    target_seed: str
    assessment_type: str = "network_web"  # network | web_app | network_web
    scope_version: str = "v1"
    approved_roots: List[str] = Field(default_factory=list)
    exclusions: List[str] = Field(default_factory=list)
    status: CellWorkflowState = CellWorkflowState.PLANNED
    current_stage: SequentialStageKey = SequentialStageKey.PREFLIGHT
    progress_percent: int = 0
    stages: Dict[str, StageExecutionRecord] = Field(default_factory=dict)
    approvals: Dict[str, StageApproval] = Field(default_factory=dict)
    approved_target_set: Optional[ApprovedTargetSet] = None
    domain_candidates: List[DomainCandidate] = Field(default_factory=list)
    service_endpoints: List[ServiceEndpointCandidate] = Field(default_factory=list)
    service_fingerprints: List[ServiceFingerprint] = Field(default_factory=list)
    web_origins: List[WebOrigin] = Field(default_factory=list)
    route_observations: List[RouteObservation] = Field(default_factory=list)
    finding_candidates: List[FindingCandidate] = Field(default_factory=list)
    raw_artifacts: List[RawEvidenceArtifact] = Field(default_factory=list)
    ai_proposals: List[AIPairedProposal] = Field(default_factory=list)
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class SequentialPipelineEngine:
    """Execution coordinator driving the 14 stages sequentially."""

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def initialize_run(
        self,
        scan_id: str,
        target_seed: str,
        assessment_type: str = "network_web",
        exclusions: Optional[List[str]] = None,
        enable_active_zap: bool = False,
        enable_nikto: bool = True,
        enable_dalfox: bool = True,
    ) -> SequentialPipelineRun:
        """Initialize pipeline with all 14 ordered stages configured."""
        exclusions = exclusions or []
        stages = {}

        stage_specs = [
            (SequentialStageKey.PREFLIGHT, "Preflight: Authorization & Scope Pinning", "preflight"),
            (SequentialStageKey.SUBFINDER, "Subfinder Passive Discovery", "subfinder"),
            (SequentialStageKey.AMASS, "Amass Passive OSINT Enrichment", "amass"),
            (SequentialStageKey.SCOPE_GATE, "Scope Resolution & Boundary Gate", "scope_resolver"),
            (SequentialStageKey.NAABU, "Naabu Bounded Port Discovery", "naabu"),
            (SequentialStageKey.NMAP, "Nmap Focused Service Probes", "nmap"),
            (SequentialStageKey.HTTPX_PROBE, "httpx-probe HTTP(S) Availability", "httpx_probe"),
            (SequentialStageKey.WHATWEB, "WhatWeb Technology Fingerprinting", "whatweb"),
            (SequentialStageKey.NUCLEI, "Nuclei Curated Template Probing", "nuclei"),
            (SequentialStageKey.ZAP_PASSIVE, "OWASP ZAP Crawl & Passive Review", "zap_passive"),
            (SequentialStageKey.NIKTO, "Nikto Server Configuration Checks", "nikto"),
            (SequentialStageKey.DALFOX, "Dalfox Targeted XSS Testing", "dalfox"),
            (SequentialStageKey.ZAP_ACTIVE, "OWASP ZAP Active Scan (Approved)", "zap_active"),
            (SequentialStageKey.EVIDENCE_CORRELATION, "Evidence Correlation & Finding Review", "correlator"),
        ]

        for key, name, tool_id in stage_specs:
            stages[key.value] = StageExecutionRecord(
                stage_key=key,
                stage_name=name,
                tool_id=tool_id,
                status=CellWorkflowState.PLANNED,
            )

        run = SequentialPipelineRun(
            scan_id=scan_id,
            target_seed=target_seed,
            assessment_type=assessment_type,
            approved_roots=[target_seed],
            exclusions=exclusions,
            stages=stages,
        )
        return run

    async def execute_full_pipeline(
        self,
        run: SequentialPipelineRun,
        auto_approve_gated_stages: bool = False,
    ) -> SequentialPipelineRun:
        """
        Execute the 14-stage pipeline sequentially, honoring scope checks,
        quarantine boundaries, and stage approvals.
        """
        run.status = CellWorkflowState.RUNNING

        # ── Stage 1: Preflight ────────────────────────────────────────────────
        await self._run_stage_preflight(run)
        if run.status == CellWorkflowState.FAILED:
            return run

        # ── Stage 2: Subfinder ────────────────────────────────────────────────
        await self._run_stage_subfinder(run)

        # ── Stage 3: Amass ────────────────────────────────────────────────────
        await self._run_stage_amass(run)

        # ── Stage 4: Scope Resolution Gate ────────────────────────────────────
        await self._run_stage_scope_gate(run)
        if run.approved_target_set and run.approved_target_set.allow_decision == "AMBIGUOUS_HELD":
            logger.warning(f"[{run.scan_id}] Targets held in AMBIGUOUS_HELD state pending scope review.")
            # Record coverage limit and proceed with any cleanly resolved targets only
            if not run.approved_target_set.targets:
                run.status = CellWorkflowState.PARTIAL
                run.error = "All discovered targets held due to ambiguous shared CDN or unresolved ownership."
                return run

        # ── Stage 5: Naabu Port Discovery ─────────────────────────────────────
        await self._run_stage_naabu(run)

        # ── Stage 6: Nmap Service Probes ──────────────────────────────────────
        await self._run_stage_nmap(run)

        # ── Stage 7: httpx_probe ──────────────────────────────────────────────
        await self._run_stage_httpx(run)

        # ── Stage 8: WhatWeb ──────────────────────────────────────────────────
        await self._run_stage_whatweb(run)

        # ── Stage 9: Nuclei ───────────────────────────────────────────────────
        await self._run_stage_nuclei(run)

        # ── Stage 10: ZAP Passive Crawl ───────────────────────────────────────
        await self._run_stage_zap_passive(run)

        # ── Stage 11: Nikto (Conditional) ─────────────────────────────────────
        await self._run_stage_nikto(run)

        # ── Stage 12: Dalfox (Conditional & Gated) ────────────────────────────
        await self._run_stage_dalfox(run, auto_approve=auto_approve_gated_stages)

        # ── Stage 13: ZAP Active Scan (Separately Approved) ───────────────────
        await self._run_stage_zap_active(run, auto_approve=auto_approve_gated_stages)

        # ── Stage 14: Evidence Correlation & Review ───────────────────────────
        await self._run_stage_evidence_correlation(run)

        run.status = CellWorkflowState.COMPLETED
        run.completed_at = datetime.now(timezone.utc)
        run.progress_percent = 100
        return run

    # ─── Individual Stage Executors ──────────────────────────────────────────

    async def _run_stage_preflight(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.PREFLIGHT.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.PREFLIGHT
        run.progress_percent = 5

        # Pin scope version and normalize seed
        clean_seed = run.target_seed.strip().lower()
        run.approved_roots = [clean_seed]
        stage_rec.targets_in_scope = [clean_seed]
        stage_rec.target_count = 1
        stage_rec.coverage_notes = f"Preflight complete. Assessment type: {run.assessment_type}. Note: Phase 1 inventory covers Network & Web Application; API assessment has known tooling gaps."
        stage_rec.status = CellWorkflowState.COMPLETED
        stage_rec.completed_at = datetime.now(timezone.utc)

    async def _run_stage_subfinder(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.SUBFINDER.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.SUBFINDER
        run.progress_percent = 10

        manifest = tool_cell_registry.get_manifest("subfinder")
        if not manifest:
            stage_rec.status = CellWorkflowState.FAILED
            stage_rec.error_message = "Subfinder manifest not found in registry"
            return

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.SUBFINDER,
            manifest=manifest,
            targets=run.approved_roots,
            profile="passive",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        cands = [r for r in result.normalized_data if isinstance(r, DomainCandidate)]
        run.domain_candidates.extend(cands)
        stage_rec.normalized_count = len(cands)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_amass(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.AMASS.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.AMASS
        run.progress_percent = 18

        manifest = tool_cell_registry.get_manifest("amass")
        targets = [c.fqdn for c in run.domain_candidates] or run.approved_roots

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.AMASS,
            manifest=manifest,
            targets=targets,
            profile="passive",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        cands = [r for r in result.normalized_data if isinstance(r, DomainCandidate)]
        run.domain_candidates.extend(cands)
        stage_rec.normalized_count = len(cands)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_scope_gate(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.SCOPE_GATE.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.SCOPE_GATE
        run.progress_percent = 25

        target_set = scope_resolver.resolve_candidate_set(
            asset_id=run.target_seed,
            scope_version=run.scope_version,
            candidates=run.domain_candidates,
            approved_roots=run.approved_roots,
            exclusions=run.exclusions,
            hold_shared_cdn=True,
        )
        # Ensure root seed is included if no candidates
        if not target_set.targets:
            target_set.targets = [run.target_seed]
            target_set.resolved_ips = scope_resolver.resolve_hostname(run.target_seed)

        run.approved_target_set = target_set
        stage_rec.target_count = len(target_set.targets)
        stage_rec.targets_in_scope = target_set.targets
        stage_rec.status = CellWorkflowState.COMPLETED
        stage_rec.completed_at = datetime.now(timezone.utc)
        stage_rec.coverage_notes = f"Scope resolver pinned {len(target_set.targets)} targets ({len(target_set.resolved_ips)} IPs). Exclusions applied: {len(target_set.exclusions_applied)}. Shared CDN: {target_set.is_cdn_or_shared}."

    async def _run_stage_naabu(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.NAABU.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.NAABU
        run.progress_percent = 35

        manifest = tool_cell_registry.get_manifest("naabu")
        targets = run.approved_target_set.targets if run.approved_target_set else run.approved_roots

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.NAABU,
            manifest=manifest,
            targets=targets,
            profile="top_100_tcp",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        endpoints = [r for r in result.normalized_data if isinstance(r, ServiceEndpointCandidate)]
        run.service_endpoints.extend(endpoints)
        stage_rec.normalized_count = len(endpoints)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_nmap(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.NMAP.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.NMAP
        run.progress_percent = 45

        manifest = tool_cell_registry.get_manifest("nmap")
        target_endpoints = [f"{e.ip_or_host}:{e.port}" for e in run.service_endpoints] or run.approved_target_set.targets

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.NMAP,
            manifest=manifest,
            targets=target_endpoints,
            profile="service_light",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        fps = [r for r in result.normalized_data if isinstance(r, ServiceFingerprint)]
        run.service_fingerprints.extend(fps)
        stage_rec.normalized_count = len(fps)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_httpx(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.HTTPX_PROBE.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.HTTPX_PROBE
        run.progress_percent = 52

        manifest = tool_cell_registry.get_manifest("httpx_probe")
        targets = [f.endpoint for f in run.service_fingerprints] or run.approved_target_set.targets

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.HTTPX_PROBE,
            manifest=manifest,
            targets=targets,
            profile="standard_probe",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        origins = [r for r in result.normalized_data if isinstance(r, WebOrigin)]
        run.web_origins.extend(origins)
        stage_rec.normalized_count = len(origins)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_whatweb(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.WHATWEB.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.WHATWEB
        run.progress_percent = 60

        manifest = tool_cell_registry.get_manifest("whatweb")
        target_urls = [f"{o.scheme}://{o.host}:{o.port}" for o in run.web_origins] or [f"https://{run.target_seed}"]

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.WHATWEB,
            manifest=manifest,
            targets=target_urls,
            profile="conservative_stealth",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        new_origins = [r for r in result.normalized_data if isinstance(r, WebOrigin)]
        stage_rec.normalized_count = len(new_origins)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_nuclei(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.NUCLEI.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.NUCLEI
        run.progress_percent = 68

        manifest = tool_cell_registry.get_manifest("nuclei")
        target_urls = [f"{o.scheme}://{o.host}:{o.port}" for o in run.web_origins] or [f"https://{run.target_seed}"]

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.NUCLEI,
            manifest=manifest,
            targets=target_urls,
            profile="curated_web",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        findings = [r for r in result.normalized_data if isinstance(r, FindingCandidate)]
        run.finding_candidates.extend(findings)
        stage_rec.normalized_count = len(findings)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_zap_passive(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.ZAP_PASSIVE.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.ZAP_PASSIVE
        run.progress_percent = 76

        manifest = tool_cell_registry.get_manifest("zap_passive")
        target_urls = [f"{o.scheme}://{o.host}:{o.port}" for o in run.web_origins] or [f"https://{run.target_seed}"]

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.ZAP_PASSIVE,
            manifest=manifest,
            targets=target_urls,
            profile="crawl_and_passive_rules",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        routes = [r for r in result.normalized_data if isinstance(r, RouteObservation)]
        findings = [r for r in result.normalized_data if isinstance(r, FindingCandidate)]
        run.route_observations.extend(routes)
        run.finding_candidates.extend(findings)
        stage_rec.normalized_count = len(routes) + len(findings)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_nikto(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.NIKTO.value]
        # Nikto is conditional: runs if web origins exist
        if not run.web_origins:
            stage_rec.status = CellWorkflowState.SKIPPED
            stage_rec.coverage_notes = "Skipped: no web server endpoints identified for server checks."
            return

        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.NIKTO
        run.progress_percent = 82

        manifest = tool_cell_registry.get_manifest("nikto")
        target_hosts = [o.host for o in run.web_origins]

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.NIKTO,
            manifest=manifest,
            targets=target_hosts,
            profile="server_misconfig_safe",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        findings = [r for r in result.normalized_data if isinstance(r, FindingCandidate)]
        run.finding_candidates.extend(findings)
        stage_rec.normalized_count = len(findings)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_dalfox(self, run: SequentialPipelineRun, auto_approve: bool = False):
        stage_rec = run.stages[SequentialStageKey.DALFOX.value]

        # Candidate parameters from routes
        param_routes = [r for r in run.route_observations if r.parameters]
        if not param_routes:
            stage_rec.status = CellWorkflowState.SKIPPED
            stage_rec.coverage_notes = "Skipped: no application routes with candidate parameters identified for XSS testing."
            return

        candidate_targets = [f"{r.origin}{r.path}?{r.parameters[0]}=test" for r in param_routes]
        manifest = tool_cell_registry.get_manifest("dalfox")

        # Stage approval verification
        approval_id = f"appr-{run.scan_id}-dalfox"
        approval = run.approvals.get(approval_id)

        if not approval:
            approval = stage_approval_service.create_approval_request(
                stage_key=SequentialStageKey.DALFOX,
                tool_id="dalfox",
                method_name="Targeted Parameter XSS Injection",
                targets=candidate_targets,
                exclusions=run.exclusions,
                profile="candidate_parameter_xss",
                rate_ceiling=5.0,
            )
            approval.approval_id = approval_id
            run.approvals[approval_id] = approval

        if auto_approve and not approval.is_approved:
            stage_approval_service.approve(
                approval=approval,
                approver="operator@argolock.internal",
                current_targets=candidate_targets,
                current_profile="candidate_parameter_xss",
                current_rate=5.0,
            )

        is_authed, reason = stage_approval_service.check_pre_dispatch_approval(
            manifest=manifest,
            approval=approval,
            current_targets=candidate_targets,
            current_profile="candidate_parameter_xss",
            current_rate=5.0,
        )

        if not is_authed:
            stage_rec.status = CellWorkflowState.APPROVAL_REQUIRED
            stage_rec.approval_id = approval_id
            stage_rec.coverage_notes = f"Approval required: {reason}"
            logger.info(f"[{run.scan_id}] Dalfox stage requires operator approval before execution.")
            return

        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.DALFOX
        run.progress_percent = 88

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.DALFOX,
            manifest=manifest,
            targets=candidate_targets,
            profile="candidate_parameter_xss",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        findings = [r for r in result.normalized_data if isinstance(r, FindingCandidate)]
        run.finding_candidates.extend(findings)
        stage_rec.normalized_count = len(findings)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_zap_active(self, run: SequentialPipelineRun, auto_approve: bool = False):
        stage_rec = run.stages[SequentialStageKey.ZAP_ACTIVE.value]
        manifest = tool_cell_registry.get_manifest("zap_active")

        target_origins = [f"{o.scheme}://{o.host}:{o.port}" for o in run.web_origins]
        if not target_origins:
            stage_rec.status = CellWorkflowState.SKIPPED
            stage_rec.coverage_notes = "Skipped: no web origins identified for active scanning."
            return

        approval_id = f"appr-{run.scan_id}-zap-active"
        approval = run.approvals.get(approval_id)

        if not approval:
            approval = stage_approval_service.create_approval_request(
                stage_key=SequentialStageKey.ZAP_ACTIVE,
                tool_id="zap_active",
                method_name="ZAP Active Application Attack Policy",
                targets=target_origins,
                exclusions=run.exclusions,
                profile="active_scan_approved",
                rate_ceiling=10.0,
                expected_traffic_class="Active web application injection attacks",
            )
            approval.approval_id = approval_id
            run.approvals[approval_id] = approval

        if auto_approve and not approval.is_approved:
            stage_approval_service.approve(
                approval=approval,
                approver="operator@argolock.internal",
                current_targets=target_origins,
                current_profile="active_scan_approved",
                current_rate=10.0,
            )

        is_authed, reason = stage_approval_service.check_pre_dispatch_approval(
            manifest=manifest,
            approval=approval,
            current_targets=target_origins,
            current_profile="active_scan_approved",
            current_rate=10.0,
        )

        if not is_authed:
            stage_rec.status = CellWorkflowState.APPROVAL_REQUIRED
            stage_rec.approval_id = approval_id
            stage_rec.coverage_notes = f"Approval required for active attack scans: {reason}"
            return

        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.ZAP_ACTIVE
        run.progress_percent = 94

        result = await tool_cell_runner.execute_cell(
            scan_id=run.scan_id,
            stage_key=SequentialStageKey.ZAP_ACTIVE,
            manifest=manifest,
            targets=target_origins,
            profile="active_scan_approved",
        )
        run.raw_artifacts.append(result.raw_artifact)
        stage_rec.raw_artifact_ref = result.raw_artifact.artifact_id
        stage_rec.raw_artifact_sha256 = result.raw_artifact.sha256_digest
        stage_rec.status = result.status
        stage_rec.duration_seconds = result.duration_seconds
        stage_rec.completed_at = datetime.now(timezone.utc)

        findings = [r for r in result.normalized_data if isinstance(r, FindingCandidate)]
        run.finding_candidates.extend(findings)
        stage_rec.normalized_count = len(findings)
        stage_rec.quarantined_count = len(result.quarantined_records)
        if result.ai_proposal:
            run.ai_proposals.append(result.ai_proposal)

    async def _run_stage_evidence_correlation(self, run: SequentialPipelineRun):
        stage_rec = run.stages[SequentialStageKey.EVIDENCE_CORRELATION.value]
        stage_rec.status = CellWorkflowState.RUNNING
        stage_rec.started_at = datetime.now(timezone.utc)
        run.current_stage = SequentialStageKey.EVIDENCE_CORRELATION
        run.progress_percent = 98

        # Group duplicate candidates by (rule_or_template_id, endpoint)
        grouped_keys: Dict[str, FindingCandidate] = {}
        for fnd in run.finding_candidates:
            key = f"{fnd.rule_or_template_id}::{fnd.endpoint}"
            if key in grouped_keys:
                primary = grouped_keys[key]
                fnd.review_state = FindingReviewState.DUPLICATE
                fnd.duplicate_of_id = primary.id
                primary.source_refs = list(set(primary.source_refs + fnd.source_refs))
            else:
                grouped_keys[key] = fnd

        candidate_count = len([f for f in run.finding_candidates if f.review_state == FindingReviewState.CANDIDATE])
        duplicate_count = len([f for f in run.finding_candidates if f.review_state == FindingReviewState.DUPLICATE])

        stage_rec.normalized_count = len(run.finding_candidates)
        stage_rec.status = CellWorkflowState.COMPLETED
        stage_rec.completed_at = datetime.now(timezone.utc)
        stage_rec.coverage_notes = (
            f"Evidence correlation complete: {candidate_count} unique candidates, "
            f"{duplicate_count} duplicate candidates linked to primary evidence. "
            f"All findings initialized as CANDIDATE pending human review. "
            f"Coverage note: API-specific testing gap exists in Phase 1 tool inventory."
        )


# Global singleton engine
sequential_pipeline_engine = SequentialPipelineEngine()
