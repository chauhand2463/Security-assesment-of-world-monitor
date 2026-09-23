from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session
import asyncio
import json
import datetime
from database.connection import get_db
from database.models import (
    Scan, Project, Vulnerability, ToolResult, Asset, Observation, AssessmentTest,
    FindingEvidence, ToolReadiness, ToolExecution, ScanStage, MLInference,
    ScanEvent,
)
from app.orchestration import events as phase7_events
from app.orchestration import state as phase7_state
from database.schemas import ScanRequest
from app.core.auth import (
    get_current_user,
    get_or_create_user_project,
    get_owned_scan,
    is_target_in_scope,
)
from app.workers.tasks import trigger_background_scan, cancel_scan
from app.agents import lifecycle
from app.config import settings
from database.models import User

router = APIRouter(prefix="/scans", tags=["scans"])

# Phase 8.5: every assessment follows exactly one authorized path.
ASSESSMENT_TYPES = ("world_monitor", "custom_target")


class ScanCreate(ScanRequest):
    """POST /scans payload: authorized target + optional job configuration.

    ``tools`` toggles which scanners take part (default: all available),
    ``severity`` applies an analysis threshold (default: report everything),
    ``profile`` is an operator hint persisted for the record.
    Phase 5/6 config keys are passed through to the assessment engine:
    ``active_testing`` (opt-in mutating tests, default False),
    ``assessment_engine`` (default True), plus optional evidence-carrying
    inputs (auth identities, SSRF validation callback, JWT case data).
    """
    tools: dict[str, bool] | None = None
    severity: str | None = None
    profile: str | None = None
    active_testing: bool | None = None
    assessment_engine: bool | None = None
    auth_identities: dict | list | None = None
    ssrf_validation_url: str | None = None
    ssrf_token: str | None = None
    jwt_tokens: list[str] | None = None
    jwt_alg_none_accepted: bool | None = None
    installed_tools: list[str] | None = None
    tools_missing: list[str] | None = None
    world_monitor: dict | None = None
    assessment_type: str | None = None
    authorization_acknowledged: bool | None = None
    max_parallel_tools: int | None = None


def _resolve_assessment_type(db: Session, user: User, payload: ScanCreate) -> str:
    """Resolve + validate the Phase 8.5 assessment path before any row is created.

    An explicit ``assessment_type`` is validated: a World Monitor path must
    reference a deployment owned by the caller (or an explicit base_url), and an
    explicit path requires the authorization acknowledgement.  When
    ``assessment_type`` is omitted the path is inferred from the presence of a
    world_monitor config so existing API clients keep working unchanged.
    """
    wm = payload.world_monitor if isinstance(payload.world_monitor, dict) else None
    explicit = payload.assessment_type
    if explicit is not None and explicit not in ASSESSMENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"assessment_type must be one of: {', '.join(ASSESSMENT_TYPES)}.",
        )

    assessment_type = explicit or ("world_monitor" if wm else "custom_target")

    if assessment_type == "world_monitor":
        if not wm or not (wm.get("target_id") or wm.get("base_url")):
            raise HTTPException(
                status_code=422,
                detail=(
                    "A world_monitor assessment requires a registered target_id "
                    "or an explicit base_url."
                ),
            )
        target_id = wm.get("target_id")
        if target_id is not None:
            from database.models import WorldMonitorTarget
            target = db.query(WorldMonitorTarget).filter(WorldMonitorTarget.id == target_id).first()
            owned = target is not None and db.query(Project).filter(
                Project.id == target.project_id, Project.user_id == user.id
            ).first() is not None
            if not owned:
                raise HTTPException(status_code=404, detail="World Monitor target not found.")

    if explicit is not None and payload.authorization_acknowledged is not True:
        raise HTTPException(
            status_code=422,
            detail="authorization_acknowledged must be true to start an assessment.",
        )

    return assessment_type


def _wm_registered_host_allowed(db, user, config, target) -> bool:
    """A world_monitor assessment is authorized when its target is a host the
    caller explicitly registered as an owned World Monitor deployment.

    Registration is itself an explicit, audit-traced authorization act, so a
    registered deployment host does not additionally need to be declared in
    the project's custom scope.  Anything else still falls through to the
    normal scope guard and is refused with 403.
    """
    wm = (config or {}).get("world_monitor") if isinstance(config, dict) else None
    if not isinstance(wm, dict):
        return False
    from database.models import WorldMonitorTarget

    def _bare_host(value: str) -> str:
        import urllib.parse
        parts = urllib.parse.urlsplit(value)
        netloc = parts.netloc or parts.path
        return netloc.split(":")[0].strip(".").lower()

    target_host = _bare_host(target)
    if not target_host:
        return False

    target_id = wm.get("target_id")
    if target_id is not None:
        row = db.query(WorldMonitorTarget).filter(WorldMonitorTarget.id == target_id).first()
        if row is None:
            return False
        owned = (db.query(Project)
                 .filter(Project.id == row.project_id, Project.user_id == user.id)
                 .first() is not None)
        if not owned:
            return False
        allowed = {_bare_host(row.base_url)}
        for extra in (row.api_base_url, row.openapi_url):
            if extra:
                allowed.add(_bare_host(extra))
        return target_host in allowed

    base_url = wm.get("base_url")
    if base_url:
        return target_host == _bare_host(base_url)
    return False


def _create_and_enqueue(db: Session, user: User, target: str, config: dict | None = None,
                        assessment_type: str | None = None,
                        authorization_acknowledged: bool | None = None) -> Scan:
    """Shared creation path: scope check -> Scan(row) -> background enqueue."""
    project = get_or_create_user_project(db, user)
    assets = db.query(Asset).filter(Asset.project_id == project.id).all()

    if not is_target_in_scope(target, project, assets):
        if not (assessment_type == "world_monitor"
                and _wm_registered_host_allowed(db, user, config, target)):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Target is outside the authorized scope for this project. "
                    "Add it to the project scope first (see /scans/scope)."
                ),
            )

    new_scan = Scan(
        project_id=project.id,
        target=target,
        status="Pending",
        stage=lifecycle.QUEUED,
        scan_config=dict(config or {}),
        assessment_type=assessment_type,
        authorization_acknowledged=(None if authorization_acknowledged is None
                                    else bool(authorization_acknowledged)),
        authorization_acknowledged_at=(datetime.datetime.utcnow()
                                       if authorization_acknowledged else None),
        logs="[System] Initializing Scan Request...\n"
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    new_scan.state = "created"  # Phase 7 state machine entry state
    db.commit()

    # Launch scanning asynchronously. The simulation flag is driven by the
    # SIMULATION_MODE configuration boundary, never hardcoded here.
    simulation = settings.simulation_mode
    new_scan.scan_config = dict(new_scan.scan_config or {})
    new_scan.scan_config["simulation"] = simulation
    db.commit()
    db.refresh(new_scan)

    # Seed the plan (total_tasks/planned list) at enqueue time so the plan is
    # visible immediately, before the background worker thread has scheduled.
    from app.agents.workflow import _seed_progress
    _seed_progress(db, new_scan, new_scan.scan_config, simulation)

    # Phase 7: record when the scan entered the worker queue so the pipeline
    # can measure how long it sat in queue before a worker picked it up.  This
    # is committed BEFORE the worker is launched so the create response reports
    # the freshly-queued row (never a stage the worker already advanced to).
    new_scan.queue_started_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(new_scan)

    trigger_background_scan(new_scan.id, simulation=simulation, config=new_scan.scan_config)

    return new_scan


@router.post("")
def create_scan(payload: ScanCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """POST /scans: create and enqueue a scan with optional configuration."""
    config = {}
    if payload.tools is not None:
        config["tools"] = {t: bool(payload.tools.get(t, True)) for t in
                           ("subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei")}
    if payload.severity:
        config["severity"] = payload.severity
    if payload.profile:
        config["profile"] = payload.profile
    # Phase 5/6 config passthrough (only explicitly provided keys are set).
    if payload.active_testing is not None:
        config["active_testing"] = bool(payload.active_testing)
    if payload.assessment_engine is not None:
        config["assessment_engine"] = bool(payload.assessment_engine)
    if payload.auth_identities is not None:
        config["auth_identities"] = payload.auth_identities
    if payload.ssrf_validation_url:
        config["ssrf_validation_url"] = payload.ssrf_validation_url
    if payload.ssrf_token:
        config["ssrf_token"] = payload.ssrf_token
    if payload.jwt_tokens is not None:
        config["jwt_tokens"] = list(payload.jwt_tokens)
    if payload.jwt_alg_none_accepted is not None:
        config["jwt_alg_none_accepted"] = bool(payload.jwt_alg_none_accepted)
    if payload.installed_tools is not None:
        config["installed_tools"] = list(payload.installed_tools)
    if payload.tools_missing is not None:
        config["tools_missing"] = list(payload.tools_missing)
    if payload.world_monitor is not None:
        config["world_monitor"] = payload.world_monitor
    if payload.max_parallel_tools is not None:
        config["max_parallel_tools"] = payload.max_parallel_tools
    if not config:
        config = None

    assessment_type = _resolve_assessment_type(db, user, payload)
    new_scan = _create_and_enqueue(
        db, user, payload.target, config,
        assessment_type=assessment_type,
        authorization_acknowledged=payload.authorization_acknowledged,
    )
    return {
        "scan_id": new_scan.id,
        "target": new_scan.target,
        "status": new_scan.status,
        "stage": new_scan.stage,
        "simulation": settings.simulation_mode,
        "coverage": new_scan.coverage,
        "assessment_type": new_scan.assessment_type,
        "authorization_acknowledged": new_scan.authorization_acknowledged,
        "created_at": new_scan.created_at,
    }


@router.post("/trigger")
def trigger_scan(payload: ScanRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Backward-compatible trigger: enqueues a scan with default configuration."""
    new_scan = _create_and_enqueue(db, user, payload.target, None)
    return {
        "scan_id": new_scan.id,
        "target": new_scan.target,
        "status": new_scan.status,
        "simulation": settings.simulation_mode,
        "created_at": new_scan.created_at,
    }


@router.get("/list")
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves scan records belonging to the authenticated user only."""
    projects = db.query(Project).filter(Project.user_id == user.id).all()
    project_ids = [p.id for p in projects]
    if not project_ids:
        return []
    scans = (
        db.query(Scan)
        .filter(Scan.project_id.in_(project_ids))
        .order_by(Scan.created_at.desc())
        .all()
    )
    return [
        {
            "id": s.id,
            "target": s.target,
            "status": s.status,
            "security_score": s.security_score,
            "created_at": s.created_at,
            "completed_at": s.completed_at,
            "assessment_type": s.assessment_type,
        }
        for s in scans
    ]


@router.get("/scope")
def get_scope(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The authenticated user's authorized scan scope for their project."""
    project = get_or_create_user_project(db, user)
    return {
        "project_id": project.id,
        "project_name": project.name,
        "scope": project.scope_json or [],
    }


@router.post("/scope")
def add_scope_entry(payload: ScanRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Add one authorized target (domain / IPv4 / CIDR) to the user's scope."""
    project = get_or_create_user_project(db, user)
    scope = list(project.scope_json or [])
    target = payload.target  # already normalized by ScanRequest
    if target not in scope:
        scope.append(target)
        project.scope_json = scope
        db.commit()
    return {"project_id": project.id, "scope": scope, "added": target}


@router.get("/{scan_id}/details")
def get_scan_details(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retrieves metadata and findings for a scan owned by the user."""
    scan = get_owned_scan(db, user, scan_id)

    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    tool_results = db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()

    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "security_score": scan.security_score,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
        "logs": scan.logs,
        "assessment_type": scan.assessment_type,
        "authorization_acknowledged": scan.authorization_acknowledged,
        "vulnerabilities": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "description": v.description,
                "remediation": v.remediation,
                "cve": v.cve,
                "cvss": v.cvss,
                "owasp": v.owasp,
                "mitre": v.mitre,
                "cwe": v.cwe,
                "rule_id": v.rule_id,
                "state": v.state or "NEW",
                "confidence": v.confidence,
                "target": v.target,
                "proof_of_concept": v.proof_of_concept,
                "evidence": v.evidence,
                "evidence_observation_ids": v.evidence_observation_ids or [],
                "resolved_at": v.resolved_at,
            }
            for v in vulnerabilities
        ],
        "tools": [{"name": tr.tool_name, "status": tr.status} for tr in tool_results]
    }


@router.get("/coverage")
def coverage_overview(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Cross-scan coverage snapshot for the authenticated user (real metrics)."""
    project_ids = [p.id for p in db.query(Project).filter(Project.user_id == user.id).all()]
    scans = db.query(Scan).filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.desc()).all() if project_ids else []
    return {
        "scans": [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "stage": s.stage,
                "coverage": s.coverage,
                "progress": s.progress or {},
                "security_score": s.security_score,
                "assessment_type": s.assessment_type,
            }
            for s in scans
        ],
        "average_coverage": None if not scans else _avg([s.coverage for s in scans if s.coverage is not None], None),
    }


def _avg(values: list, default=None):
    return default if not values else round(sum(values) / len(values), 2)


@router.get("/summary")
def scan_summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Aggregated, real metrics for the dashboard, across the user's own scans.

    Every number is derived from persisted rows owned by the authenticated
    user; there are no hardcoded or sample figures here.
    """
    project_ids = [p.id for p in db.query(Project).filter(Project.user_id == user.id).all()]
    scans = []
    open_findings = []
    open_ports = []

    if project_ids:
        scans = db.query(Scan).filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.asc()).all()
        scan_ids = [s.id for s in scans]

        open_states = {"NEW", "CONFIRMED"}
        open_findings = [
            f for f in db.query(Vulnerability).filter(Vulnerability.scan_id.in_(scan_ids)).all()
            if (f.state or "NEW").upper() in open_states
        ]

        ports = db.query(Asset).filter(
            Asset.project_id.in_(project_ids), Asset.type == "port"
        ).all()
        open_ports = [
            a for a in ports
            if (a.metadata_json or {}).get("state") == "open" or a.value.endswith("/tcp")
        ]

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in open_findings:
        sev = (f.severity or "").capitalize()
        if sev in severity_counts:
            severity_counts[sev] += 1

    status = {"Pending": 0, "Running": 0, "Completed": 0, "Failed": 0}
    for s in scans:
        status[s.status] = status.get(s.status, 0) + 1

    return {
        "total_findings": len(open_findings),
        "open_findings": len(open_findings),
        "severity_distribution": severity_counts,
        "open_ports_total": len({p.value for p in open_ports}),
        "open_ports": sorted({p.value for p in open_ports}),
        "scans_total": len(scans),
        "scans_by_status": status,
        "score_history": [
            {"target": s.target, "score": s.security_score, "created_at": s.created_at, "id": s.id}
            for s in scans
        ],
    }


def _assessment_coverage(db: Session, scan_id: int) -> dict | None:
    """Phase 5 coverage summary persisted as the ``native_assessment`` tool result."""
    row = (
        db.query(ToolResult)
        .filter(ToolResult.scan_id == scan_id, ToolResult.tool_name == "native_assessment")
        .first()
    )
    if not row or not row.raw_output:
        return None
    try:
        return json.loads(row.raw_output)
    except (ValueError, TypeError):
        return None


def _assessment_tests(db: Session, scan_id: int) -> list[dict]:
    rows = (
        db.query(AssessmentTest)
        .filter(AssessmentTest.scan_id == scan_id)
        .order_by(AssessmentTest.id.asc())
        .all()
    )
    return [
        {
            "test_id": t.test_id,
            "name": t.name,
            "category": t.category,
            "status": t.status,
            "reason": t.reason,
            "active": bool(t.active),
            "observation_ids": t.observation_ids or [],
            "finding_ids": t.finding_ids or [],
        }
        for t in rows
    ]


def _finding_evidence(db: Session, finding_id: int) -> list[dict]:
    rows = (
        db.query(FindingEvidence)
        .filter(FindingEvidence.finding_id == finding_id)
        .order_by(FindingEvidence.id.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "observation_id": e.observation_id,
            "evidence_type": e.evidence_type,
            "expected": e.expected,
            "actual": e.actual,
            "security_boundary": e.security_boundary,
            "redaction_status": e.redaction_status,
            # Phase 6 evidence integrity metadata.
            "request_hash": e.request_hash,
            "response_hash": e.response_hash,
            "original_size": e.original_size,
            "captured_size": e.captured_size,
            "truncated": e.truncated,
        }
        for e in rows
    ]


def _vulnerability_dict(db: Session, v: Vulnerability) -> dict:
    """Serialize a finding including Phase 5 assessment fields and evidence."""
    from app.assess import finding_lifecycle as lifecycle

    return {
        "id": v.id,
        "title": v.title,
        "severity": v.severity,
        "description": v.description,
        "remediation": v.remediation,
        "cve": v.cve,
        "cvss": v.cvss,
        "owasp": v.owasp,
        "mitre": v.mitre,
        "cwe": v.cwe,
        "rule_id": v.rule_id,
        "state": v.state or "NEW",
        "confidence": v.confidence,
        "target": v.target,
        "proof_of_concept": v.proof_of_concept,
        "evidence": v.evidence,
        "evidence_observation_ids": v.evidence_observation_ids or [],
        "resolved_at": v.resolved_at,
        # Phase 5 assessment metadata (null for Phase 3 findings).
        "category": v.category,
        "endpoint": v.endpoint,
        "http_method": v.http_method,
        "source_test": v.source_test,
        "source_tool": v.source_tool,
        "validation_reason": v.validation_reason,
        "impact": v.impact,
        "evidence_records": _finding_evidence(db, v.id),
        # Phase 6 lifecycle + reporting fields.
        "status": v.status or lifecycle.STATUS_CONFIRMED,
        "affected_component": v.affected_component,
        "parameter": v.parameter,
        "cvss_version": v.cvss_version,
        "cvss_vector": v.cvss_vector,
        "cvss_score": v.cvss_score,
        "business_impact": v.business_impact,
        "technical_impact": v.technical_impact,
        "impact_details": v.impact_details,
        "remediation_details": v.remediation_details,
        "fingerprint": v.fingerprint or v.dedup_key,
        "first_seen": v.first_seen,
        "last_seen": v.last_seen,
    }


@router.get("/{scan_id}")
def get_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Full scan detail: lifecycle stage, progress, coverage, findings, tools."""
    scan = get_owned_scan(db, user, scan_id)
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    tool_results = db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()
    observations = db.query(Observation).filter(Observation.scan_id == scan_id).count()
    assessment_tests = _assessment_tests(db, scan_id)
    from app.assess.sih import coverage_by_area
    from app.orchestration.dimensions import dimension_coverage

    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "stage": scan.stage or lifecycle.QUEUED,
        "security_score": scan.security_score,
        "coverage": scan.coverage,
        "progress": scan.progress or {},
        "scan_config": scan.scan_config or {},
        "assessment_type": scan.assessment_type,
        "authorization_acknowledged": scan.authorization_acknowledged,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "cancelled_at": scan.cancelled_at,
        "error": scan.error,
        "logs": scan.logs,
        "simulation": bool((scan.scan_config or {}).get("simulation", settings.simulation_mode)),
        "vulnerabilities": [_vulnerability_dict(db, v) for v in vulnerabilities],
        "observations_count": observations,
        "dimensions": dimension_coverage(db, scan.id, scan.target or ""),
        "assessment": {
            "coverage": _assessment_coverage(db, scan_id),
            "tests": assessment_tests,
            "sih": coverage_by_area(assessment_tests),
        },
        "tools": [
            {"name": tr.tool_name, "status": tr.status, "raw_output": tr.raw_output}
            for tr in tool_results
        ],
    }


@router.get("/{scan_id}/observations")
def get_scan_observations(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Persisted evidence observations for a scan owned by the user.

    Phase 10.4 provenance: each observation carries ``tool_execution_id`` --
    the exact ``tool_executions`` row that produced it -- plus the execution's
    real terminal state, duration and parsed-observation count.  NULL provenance
    is honest: it means the observation came from a path that does not create a
    ToolExecution row (e.g. Phase 5 engine-native HTTP observations).
    """
    get_owned_scan(db, user, scan_id)
    from database.models import ToolExecution

    rows = db.query(Observation).filter(Observation.scan_id == scan_id).order_by(Observation.id.asc()).all()
    ex_ids = {o.tool_execution_id for o in rows if o.tool_execution_id}
    executions = {}
    if ex_ids:
        for ex in db.query(ToolExecution).filter(ToolExecution.id.in_(ex_ids)).all():
            executions[ex.id] = ex
    out = []
    for o in rows:
        ex = executions.get(o.tool_execution_id) if o.tool_execution_id else None
        out.append({
            "id": o.id, "tool": o.tool_name, "kind": o.kind, "subject": o.subject,
            "data": o.data_json or {}, "raw": o.raw_output or "", "created_at": o.created_at,
            "observation_type": o.observation_type or o.kind, "source": o.source,
            "status": o.status, "fingerprint": o.fingerprint, "asset_id": o.asset_id,
            "request": o.request_json, "response": o.response_json,
            "tool_execution_id": o.tool_execution_id,
            "provenance": None if ex is None else {
                "execution_id": ex.id,
                "tool": ex.tool,
                "stage": ex.stage,
                "attempt": ex.attempt,
                "status": ex.status,
                "duration_ms": ex.duration_ms,
                "parsed_observations": ex.parsed_observations or 0,
                "started_at": ex.started_at.isoformat() if ex.started_at else None,
                "finished_at": ex.finished_at.isoformat() if ex.finished_at else None,
                "exit_code": ex.exit_code,
                "termination_reason": ex.termination_reason,
            },
        })
    return out


@router.get("/{scan_id}/assets")
def get_scan_assets(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Asset graph rows linked to a scan's evidence (owned by the user).

    Phase 9: deduplicated assets whose scan surfaced them first, with their
    real parent edges and any sibling edges discoverable from linked
    observations.  Nothing is invented: rows only exist if persistence put them
    there.
    """
    scan = get_owned_scan(db, user, scan_id)
    obs_rows = db.query(Observation).filter(Observation.scan_id == scan_id).all()
    asset_ids = sorted({o.asset_id for o in obs_rows if o.asset_id})
    scan_assets = (
        db.query(Asset).filter(Asset.project_id == scan.project_id, Asset.scan_id == scan_id)
        .order_by(Asset.id.asc()).all()
    )
    scoped = {a.id: a for a in scan_assets}
    for aid in asset_ids:
        row = db.query(Asset).filter(Asset.id == aid).first()
        if row and row.id not in scoped:
            scoped[row.id] = row
    rows_sorted = sorted(scoped.values(), key=lambda a: a.id)
    return [
        {"id": a.id, "type": a.type, "value": a.value,
         "source": a.source or (a.metadata_json or {}).get("source"),
         "metadata": a.metadata_json or {}, "created_at": a.created_at,
         "parent_asset_id": a.parent_asset_id,
         "children": sorted({c.id for c in a.children}, key=lambda x: x)}
        for a in rows_sorted
    ]


@router.get("/{scan_id}/findings")
def get_scan_findings(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Persisted findings (evidence-backed) for a scan owned by the user."""
    get_owned_scan(db, user, scan_id)
    rows = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).order_by(Vulnerability.id.asc()).all()
    return [_vulnerability_dict(db, v) for v in rows]


@router.get("/{scan_id}/coverage")
def get_scan_coverage(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Coverage for one scan: planned vs completed tasks, honest percentages.

    Phase 10.11 adds ``dimensions``: the distinct hosts / ports / URLs actually
    observed from real persisted rows (never guessed), grouped by tool.
    """
    scan = get_owned_scan(db, user, scan_id)
    progress = scan.progress or {}
    from app.orchestration.dimensions import dimension_coverage

    return {
        "scan_id": scan.id,
        "target": scan.target,
        "coverage": scan.coverage,
        "completed_tasks": progress.get("completed_tasks", 0),
        "failed_tasks": progress.get("failed_tasks", 0),
        "total_tasks": progress.get("total_tasks", 0),
        "completed_tools": progress.get("completed_tools", 0),
        "total_tools": progress.get("total_tools", 0),
        "percent": progress.get("percent", 0),
        "planned_tasks": progress.get("planned_tasks", []),
        "security_score": scan.security_score,
        "assessment": _assessment_coverage(db, scan.id),
        "dimensions": dimension_coverage(db, scan.id, scan.target or ""),
    }


@router.post("/{scan_id}/cancel")
def cancel_scan_job(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Request cancellation of a queued/running scan owned by the user."""
    scan = get_owned_scan(db, user, scan_id)
    if scan.stage and lifecycle.is_terminal(scan.stage):
        return {"scan_id": scan.id, "status": scan.status, "message": "Scan already in a terminal state.", "stage": scan.stage}

    requested = cancel_scan(scan_id)
    if not requested:
        # Never enqueued (e.g. backfilled row): mark cancelled immediately.
        scan.stage = lifecycle.CANCELLED
        scan.status = "Cancelled"
        scan.cancelled_at = datetime.datetime.utcnow()
        scan.updated_at = datetime.datetime.utcnow()
        scan.logs += "[Worker] Scan cancelled by user; remaining stages abandoned.\n"
        db.commit()
    else:
        scan.cancel_requested = True
        scan.updated_at = datetime.datetime.utcnow()
        db.commit()
    return {"scan_id": scan.id, "status": "Cancelled", "stage": lifecycle.CANCELLED, "message": "Cancellation requested."}


@router.get("/{scan_id}/events")
async def stream_scan_events(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
):
    """SSE endpoint streaming real, persisted scan lifecycle events.

    Phase 10.8 (G5): the stream is a typed cursor over the ``scan_events``
    ledger.  Every event carries an ``id:`` line equal to the ``ScanEvent`` row
    id; a reconnecting client sends ``Last-Event-ID`` to resume exactly where it
    stopped (no re-delivery, no gaps).  For legacy/backfilled scans that predate
    the event ledger the endpoint falls back to the original diff-based
    synthesis, so the wire vocabulary is unchanged.
    """
    get_owned_scan(db, user, scan_id)
    start_cursor = 0
    if last_event_id and last_event_id.strip().lstrip("-").isdigit():
        start_cursor = max(int(last_event_id), 0)

    async def event_generator():
        if db.query(ScanEvent).filter(ScanEvent.scan_id == scan_id).first() is None:
            # Legacy/backfilled scan: no typed ledger exists.  Keep the original
            # poll-and-diff behaviour (default wire unchanged).
            async for out in _legacy_diff_stream(scan_id):
                yield out
            return

        cursor = start_cursor
        sent_done = False
        while True:
            local_db = next(get_db())
            try:
                scan = local_db.query(Scan).filter(Scan.id == scan_id).first()
                if not scan:
                    yield f"data: {json.dumps({'type': 'error', 'error': 'Scan ID not found'})}\n\n"
                    break

                page = (
                    local_db.query(ScanEvent)
                    .filter(ScanEvent.scan_id == scan_id, ScanEvent.id > cursor)
                    .order_by(ScanEvent.id.asc())
                    .limit(200)
                    .all()
                )
                if not page:
                    if lifecycle.is_terminal(scan.stage or ""):
                        if not sent_done:
                            yield f"id: {cursor}\ndata: {json.dumps(_done_event(scan))}\n\n"
                        break
                    await asyncio.sleep(0.5)
                    continue

                for ev in page:
                    cursor = ev.id
                    wire = _scan_event_to_wire(ev, scan)
                    if wire is None:
                        # Internal ledger row (state/preflight/validation/…):
                        # advance the cursor without re-emitting it on this wire.
                        continue
                    yield f"id: {ev.id}\n"
                    yield f"data: {json.dumps(wire)}\n\n"
                    if wire["type"] == "done":
                        sent_done = True
                        break
                if sent_done:
                    break
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
                break
            finally:
                local_db.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _scan_event_to_wire(ev: ScanEvent, scan: Scan) -> dict:
    """Map one ledger row onto the stable SSE wire vocabulary.

    Only the events the live dashboard consumes (stage/tool/progress/finding/
    done/error) are shaped here; finer-grained phases 8/9 events remain on the
    ``/typed-events`` stream and are not re-emitted, keeping this endpoint's
    contract unchanged.
    """
    d = ev.data or {}
    t = ev.event_type
    now = datetime.datetime.utcnow().isoformat()
    if t == phase7_events.EVENT_STAGE:
        return {"type": "stage", "stage": d.get("stage"), "status": d.get("status"),
                "timestamp": now}
    if t == phase7_events.EVENT_TOOL:
        return {"type": "tool", "tool": d.get("tool"), "status": d.get("status"),
                "timestamp": now}
    if t in (phase7_events.EVENT_PROGRESS, phase7_events.EVENT_COVERAGE):
        percent = d.get("percent")
        if percent is None:
            percent = d.get("coverage_percent")
        return {"type": "progress", "percent": percent,
                "coverage": scan.coverage, "security_score": scan.security_score,
                "timestamp": now}
    if t in (phase7_events.EVENT_FINDING,
             phase7_events.EVENT_FINDING_CANDIDATE,
             phase7_events.EVENT_FINDING_VERIFIED,
             phase7_events.EVENT_FINDING_REJECTED):
        return {"type": "finding", "id": d.get("id"), "title": d.get("title"),
                "severity": d.get("severity"), "timestamp": now}
    if t == phase7_events.EVENT_DONE:
        return _done_event(scan)
    if t == phase7_events.EVENT_ERROR:
        return {"type": "error", "error": d.get("reason") or "scan error",
                "timestamp": now}
    # Everything else (state, preflight, validation, asset.discovered,
    # observation.created) stays internal to the typed ledger: the cursor
    # advances past it but nothing is emitted on this legacy wire.
    return None


def _done_event(scan: Scan) -> dict:
    return {"type": "done", "status": scan.status, "stage": scan.stage or lifecycle.QUEUED,
            "coverage": scan.coverage, "security_score": scan.security_score}


async def _legacy_diff_stream(scan_id: int):
    """Original diff-based SSE stream for scans without an event ledger."""
    last = {"stage": None, "tools": set(), "findings": set(), "progress": None,
            "completed_at": None}
    while True:
        local_db = next(get_db())
        try:
            scan = local_db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                yield f"data: {json.dumps({'type': 'error', 'error': 'Scan ID not found'})}\n\n"
                break

            tools = local_db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()
            findings = local_db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

            if (scan.stage or lifecycle.QUEUED) != last["stage"]:
                last["stage"] = scan.stage or lifecycle.QUEUED
                yield f"data: {json.dumps({'type': 'stage', 'stage': last['stage'], 'status': scan.status, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

            for tr in tools:
                if tr.id not in last["tools"]:
                    last["tools"].add(tr.id)
                    yield f"data: {json.dumps({'type': 'tool', 'tool': tr.tool_name, 'status': tr.status, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

            for f in findings:
                if f.id not in last["findings"]:
                    last["findings"].add(f.id)
                    yield f"data: {json.dumps({'type': 'finding', 'id': f.id, 'title': f.title, 'severity': f.severity, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

            progress = (scan.progress or {}).get("percent")
            if progress != last["progress"]:
                last["progress"] = progress
                yield f"data: {json.dumps({'type': 'progress', 'percent': progress, 'coverage': scan.coverage, 'security_score': scan.security_score, 'timestamp': datetime.datetime.utcnow().isoformat()})}\n\n"

            if scan.completed_at and scan.completed_at != last["completed_at"]:
                last["completed_at"] = scan.completed_at
                yield f"data: {json.dumps({'type': 'done', 'status': scan.status, 'stage': scan.stage or lifecycle.QUEUED, 'coverage': scan.coverage, 'security_score': scan.security_score})}\n\n"
                break

            if lifecycle.is_terminal(scan.stage or ""):
                yield f"data: {json.dumps({'type': 'done', 'status': scan.status, 'stage': scan.stage, 'coverage': scan.coverage, 'security_score': scan.security_score})}\n\n"
                break

            await asyncio.sleep(0.5)
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
            break
        finally:
            local_db.close()


@router.get("/{scan_id}/execution-plan")
def get_scan_execution_plan(scan_id: int, user: User = Depends(get_current_user),
                            db: Session = Depends(get_db)):
    """Phase 10.3 execution plan: how this scan's plan was really run.

    Returns the ordered plan that was executed (stages + tools), the scheduling
    decision (sequential/parallel + the bounded concurrency that was applied),
    and the honest per-state counters from tool results.  Never fabricated: a
    counter only reflects tool outcomes the pipeline actually observed.
    """
    scan = get_owned_scan(db, user, scan_id)

    from database.models import ScanExecution
    row = (db.query(ScanExecution)
           .filter(ScanExecution.scan_id == scan.id)
           .order_by(ScanExecution.id.desc())
           .first())
    from app.execution.scheduler import group_plan, max_parallel_tools
    plan = (row.plan if row is not None and row.plan is not None
            else group_plan(scan.scan_config or {}))
    return {
        "scan_id": scan.id,
        "exists": row is not None,
        "strategy": row.strategy if row is not None else "sequential",
        "max_parallel_tools": (row.max_parallel_tools if row is not None
                               else max_parallel_tools(scan.scan_config or {})),
        "status": row.status if row is not None else "pending",
        "planned_tools": row.planned_tools if row is not None
        else sum(len(g.get("tools") or ()) for g in plan),
        "started_tools": row.started_tools if row is not None else 0,
        "completed_tools": row.completed_tools if row is not None else 0,
        "failed_tools": row.failed_tools if row is not None else 0,
        "skipped_tools": row.skipped_tools if row is not None else 0,
        "started_at": row.started_at.isoformat() if row and row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row and row.finished_at else None,
        "duration_ms": row.duration_ms if row is not None else None,
        "plan": plan,
    }


@router.get("/{scan_id}/assessment")
def get_scan_assessment(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Phase 6 assessment summary: coverage, aggregates, completeness, snapshot.

    Describes the assessment performed (coverage %, executed/failed/skipped
    tests, lifecycle aggregates), never a security verdict on the target.
    """
    scan = get_owned_scan(db, user, scan_id)
    from app.assess import summary as assess_summary

    coverage = _assessment_coverage(db, scan_id)
    return assess_summary.summary_from_scan(db, scan, coverage)


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: int,
    format: str = "json",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Phase 6 report export (json|markdown|html|pdf).

    The report is deterministic, built only from persisted state, and preserves
    finding ids, evidence ids, coverage, limitations, the registry fingerprint
    and timestamps.  Every export is recorded with a content hash for
    reproducibility.  HTML and PDF are real, self-contained exports rendered
    from the same deterministic section model.
    """
    scan = get_owned_scan(db, user, scan_id)
    fmt = (format or "json").lower()
    if fmt not in ("json", "markdown", "html", "pdf"):
        raise HTTPException(status_code=400,
                            detail="format must be 'json', 'markdown', 'html' or 'pdf'.")

    from app.reporting import builder as report_builder
    from app.reporting import export as report_export
    from app.reporting import html_renderer, pdf_writer

    report = report_builder.build(db, scan)
    markdown = report.markdown
    json_payload = report.json_content

    if fmt == "json":
        payload = report_export.render_json(json_payload)
        response = {
            "format": "json",
            "scan_id": scan.id,
            "target": scan.target,
            "generated_at": report.generated_at,
            "registry_fingerprint": report.registry_fingerprint,
            "config_fingerprint": report.config_fingerprint,
            "content_hash": report_export.content_hash(payload),
            "report": json_payload,
        }
        record_payload = payload
        content_json = json_payload
        content_markdown = None
        content_html = None
        content_pdf = None
    elif fmt == "markdown":
        payload = report_export.render_markdown(markdown)
        response = {
            "format": "markdown",
            "scan_id": scan.id,
            "target": scan.target,
            "generated_at": report.generated_at,
            "registry_fingerprint": report.registry_fingerprint,
            "config_fingerprint": report.config_fingerprint,
            "content_hash": report_export.content_hash(payload),
            "report": payload,
        }
        record_payload = payload
        content_json = None
        content_markdown = payload
        content_html = None
        content_pdf = None
    elif fmt == "html":
        sections = [_section_dict(s) for s in report.sections]
        html_doc = html_renderer.render_html(
            sections,
            title=scan.target,
            generated_at=report.generated_at,
            fingerprint=report.registry_fingerprint,
            config_fingerprint=report.config_fingerprint,
        )
        payload = report_export.render_html(html_doc)
        response = {
            "format": "html",
            "scan_id": scan.id,
            "target": scan.target,
            "generated_at": report.generated_at,
            "registry_fingerprint": report.registry_fingerprint,
            "config_fingerprint": report.config_fingerprint,
            "content_hash": report_export.content_hash(payload),
            "report": payload,
        }
        record_payload = payload
        content_json = None
        content_markdown = None
        content_html = html_doc
        content_pdf = None
    else:  # pdf
        sections = [_section_dict(s) for s in report.sections]
        pdf_bytes = pdf_writer.render_pdf(
            sections,
            title=f"Assessment Report - {scan.target}",
            generated_at=report.generated_at,
            fingerprint=report.registry_fingerprint or "",
        )
        response = {
            "format": "pdf",
            "scan_id": scan.id,
            "target": scan.target,
            "generated_at": report.generated_at,
            "registry_fingerprint": report.registry_fingerprint,
            "config_fingerprint": report.config_fingerprint,
            "content_hash": report_export.content_hash_bytes(pdf_bytes),
            "content_length": len(pdf_bytes),
        }
        record_payload = pdf_bytes
        content_json = None
        content_markdown = None
        content_html = None
        content_pdf = pdf_bytes

    report_export.persist_export(
        db,
        scan_id=scan.id,
        fmt=fmt,
        payload=record_payload,
        content_json=content_json,
        content_markdown=content_markdown,
        content_html=content_html,
        content_pdf=content_pdf,
        registry_fingerprint=report.registry_fingerprint,
        config_fingerprint=report.config_fingerprint,
        user_id=str(getattr(user, "id", "")),
    )

    if fmt == "pdf":
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=cyberagent_report_{scan.id}.pdf"},
        )
    return response


def _section_dict(section) -> dict:
    return {"id": section.id, "title": section.title, "markdown": section.markdown}


@router.get("/{scan_id}/stream")
async def stream_scan_logs(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Server Sent Events (SSE) logs streaming endpoint for realtime UI tracking.

    Communicated via a native EventSource, which cannot attach Authorization
    headers, so the session token is also accepted through the ``token``
    query parameter when present.
    """
    get_owned_scan(db, user, scan_id)

    async def log_generator():
        last_length = 0
        while True:
            # Re-fetch scan status inside generator loop
            local_db = next(get_db())
            try:
                scan = local_db.query(Scan).filter(Scan.id == scan_id).first()
                if not scan:
                    yield f"data: {json.dumps({'error': 'Scan ID not found'})}\n\n"
                    break

                current_logs = scan.logs or ""
                # Stream only new log content
                if len(current_logs) > last_length:
                    new_chunk = current_logs[last_length:]
                    last_length = len(current_logs)
                    yield f"data: {json.dumps({'logs': new_chunk, 'status': scan.status, 'score': scan.security_score})}\n\n"

                if scan.status in ["Completed", "Failed"]:
                    # Send a final resolution event and end stream
                    yield f"data: {json.dumps({'status': scan.status, 'done': True, 'score': scan.security_score})}\n\n"
                    break

                await asyncio.sleep(0.5)
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break
            finally:
                local_db.close()

    return StreamingResponse(log_generator(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Phase 7 execution-platform endpoints
# ---------------------------------------------------------------------------
@router.get("/{scan_id}/state")
def get_scan_state(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Phase 7 state machine summary for a scan (+ legal next transitions)."""
    scan = get_owned_scan(db, user, scan_id)
    current = scan.state or phase7_state.CREATED
    return {
        "scan_id": scan.id,
        "state": current,
        "coarse_status": scan.status,
        "stage": scan.stage or lifecycle.QUEUED,
        "coarse_completion": phase7_state.coarse_completion(current),
        "terminal": phase7_state.is_terminal(current),
        "transitions": sorted(phase7_state.ALL)
        if phase7_state.is_terminal(current)
        else phase7_state.ALL,
        "queue_waited_ms": scan.queue_waited_ms,
        "updated_at": scan.updated_at,
    }


@router.get("/{scan_id}/stages")
def get_scan_stages(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Real per-stage progress ledger for one scan."""
    get_owned_scan(db, user, scan_id)
    rows = db.query(ScanStage).filter(ScanStage.scan_id == scan_id).order_by(ScanStage.id.asc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "order": r.order,
            "status": r.status,
            "reason": r.reason,
            "tools": r.tools or [],
            "tests_executed": r.tests_executed or 0,
            "observations": r.observations or 0,
            "candidates": r.candidates or 0,
            "confirmed_findings": r.confirmed_findings or 0,
            "errors": r.errors or {},
            "duration_ms": r.duration_ms,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
        }
        for r in rows
    ]


@router.get("/{scan_id}/executions")
def get_scan_executions(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Real execution ledger: every tool attempt/skip with process telemetry."""
    get_owned_scan(db, user, scan_id)
    rows = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).order_by(ToolExecution.id.asc()).all()
    return [
        {
            "id": r.id,
            "stage": r.stage,
            "tool": r.tool,
            "adapter": r.adapter,
            "attempt": r.attempt,
            "status": r.status,
            "executable": r.executable,
            "tool_version": r.tool_version,
            "target": r.target,
            "command_redacted": r.command_redacted,
            "exit_code": r.exit_code,
            "duration_ms": r.duration_ms,
            "stdout_size": r.stdout_size,
            "stderr_size": r.stderr_size,
            "truncated": bool(r.stdout_truncated or r.stderr_truncated),
            "parsed_observations": r.parsed_observations or 0,
            "cancellation_state": r.cancellation_state,
            "termination_reason": r.termination_reason,
            "error_code": r.error_code,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
        }
        for r in rows
    ]


@router.get("/{scan_id}/readiness")
def get_scan_readiness(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Preflight snapshot: what was installed/disabled/missing when the scan ran."""
    scan = get_owned_scan(db, user, scan_id)
    rows = db.query(ToolReadiness).filter(ToolReadiness.scan_id == scan_id).order_by(ToolReadiness.id.asc()).all()
    return {
        "scan_id": scan.id,
        "preflight": scan.preflight_json or {},
        "tools": [
            {
                "tool": r.tool,
                "status": r.status,
                "executable": r.executable,
                "version": r.version,
                "adapter": r.adapter,
                "category": r.category,
                "enabled": bool(r.enabled),
                "reason": r.reason,
                "checked_at": r.checked_at,
            }
            for r in rows
        ],
    }


@router.get("/{scan_id}/typed-events")
def get_scan_typed_events(
    scan_id: int,
    cursor: int = 0,
    limit: int = 500,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Replay the ordered Phase 7 typed event stream from a cursor."""
    get_owned_scan(db, user, scan_id)
    if limit < 1 or limit > 2000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 2000.")
    return phase7_events.replay(db, scan_id, cursor=cursor, limit=limit)


@router.get("/{scan_id}/ml-advisory")
def get_scan_ml_advisory(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The deterministic advisory-only record for a scan (no model predictions)."""
    scan = get_owned_scan(db, user, scan_id)
    row = (
        db.query(MLInference)
        .filter(MLInference.scan_id == scan_id)
        .order_by(MLInference.id.desc())
        .first()
    )
    if row is None:
        return {"scan_id": scan.id, "advisory": None}
    return {
        "scan_id": scan.id,
        "id": row.id,
        "status": row.status,
        "model_name": row.model_name,
        "model_version": row.model_version,
        "feature_schema_version": row.feature_schema_version,
        "training_status": row.training_status,
        "generated_at": row.generated_at,
        "advisory": row.advisory_json,
    }


@router.get("/{scan_id}/compare")
def compare_scans(
    scan_id: int,
    with_scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cross-scan finding diff: added/removed/retained/reintroduced fingerprints."""
    scan_a = get_owned_scan(db, user, scan_id)
    scan_b = get_owned_scan(db, user, with_scan_id)
    from app.assess import tracking

    diff = tracking.compare(db, scan_a.id, scan_b.id)
    diff["same_target"] = (scan_a.target or "").strip() == (scan_b.target or "").strip()
    if not diff["same_target"]:
        diff["note"] = "Scans have different targets; the diff compares raw fingerprints only."
    return diff


@router.post("/{scan_id}/retry")
def retry_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Re-enqueue a terminal scan for another run (evidence is preserved;
    rule dedup prevents duplicate findings on re-assessment)."""
    scan = get_owned_scan(db, user, scan_id)
    current = scan.state or phase7_state.CREATED
    if not phase7_state.is_terminal(current):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot retry a scan in non-terminal state {current!r}.",
        )
    if current != phase7_state.CANCELLED:
        scan.state = phase7_state.CREATED
    scan.stage = lifecycle.QUEUED
    scan.status = "Pending"
    scan.error = None
    scan.completed_at = None
    scan.cancelled_at = None
    scan.queue_waited_ms = None
    scan.queue_started_at = datetime.datetime.utcnow()
    scan.preflight_json = None
    scan.progress = lifecycle.empty_progress()
    scan.logs = (scan.logs or "") + "[System] Retry requested; re-enqueuing for a new run...\n"
    scan.updated_at = datetime.datetime.utcnow()
    db.commit()

    config = dict(scan.scan_config or {})
    simulation = config.get("simulation", settings.simulation_mode)
    trigger_background_scan(scan.id, simulation=simulation, config=config)
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "state": scan.state,
        "stage": scan.stage,
        "simulation": simulation,
    }