"""Phase 7 pipeline driver: run one real scan end to end.

``orchestrate_scan_phase7`` is the real-execution orchestrator.  It advances the
Phase 7 state machine (``Scan.state``), runs the 13 pipeline stages, and persists
the honest execution trail that everything else reads back:

  * ``scan_stages``     -- one row per stage with real counters,
  * ``scan_events``     -- typed, ordered stream for live dashboards/replay,
  * ``tool_executions`` -- every real attempt/skip with process telemetry,
  * ``tool_readiness`` + ``preflight_json`` -- what was actually available,
  * ``finding_validations`` / ``finding_observation_links`` -- how every
    candidate was (or was not) deterministically re-confirmed,
  * ``ml_inferences``   -- the advisory-only deterministic record.

Findings are always derived from persisted observations (rules + the Phase 5
native engine); external tool output only ever produces candidate status.
Cancellation is cooperative and honored between stages and inside adapters.
"""
from __future__ import annotations

import datetime
import logging
import threading

from sqlalchemy import func

from app.agents import lifecycle
from app.agents.workflow import (
    SEVERITY_THRESHOLD,
    _check_cancel,
    _enabled_tools,
    _finding_dict,
    _merge_config,
    _persist_progress,
    _persisted_finding,
    _scan_observations,
    generate_markdown_report_content,
)
from app.assess import finding_rules
from app.orchestration import events, executions, preflight
from app.orchestration import state as SM
from app.orchestration.stages import (
    STAGE_ORDER,
    STAGE_TOOLS,
    TOOL_TO_STAGE,
    enabled as stage_enabled,
    plan_tasks,
    plan_tool_count,
)
from app.workers.tasks import ScanCancelled, registry
from app.tools import scanner_tools

logger = logging.getLogger("cyberagent.pipeline")

# A gap is anything that kept a planned tool from actually contributing:
# a missing binary is recorded as not_installed and counts as a gap (the scan
# may never claim full completion when a tool could not run).  Skips caused by
# operator configuration remain deliberate decisions, not gaps.
_FAILED_STATES = {scanner_tools.STATE_EXECUTION_FAILED,
                  scanner_tools.STATE_TIMEOUT, scanner_tools.STATE_PARSE_FAILED,
                  scanner_tools.STATE_NOT_INSTALLED}


def orchestrate_scan_phase7(scan_id: int, simulation: bool = True,
                            config: dict | None = None):
    """Run a real scan through the Phase 7 pipeline as a background job."""
    if simulation:
        # Simulation keeps the Phase 4 orchestrator exactly (tests + SSE rely on
        # its behaviour); Phase 7 is the real-execution path only.
        from app.agents.workflow import orchestrate_scan
        return orchestrate_scan(scan_id, simulation=True, config=config)

    from database.connection import SessionLocal
    from database.models import Scan

    db = SessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            logger.error(f"Scan ID {scan_id} not found in database.")
            return

        job = registry.get(scan_id)
        if job is not None:
            job.attach_thread(threading.current_thread())

        config = _merge_config(config, scan.scan_config)
        scan.scan_config = config
        scan.started_at = datetime.datetime.utcnow()
        _move_state(db, scan, SM.QUEUED, "accepted; waiting for a worker")
        _set_legacy(db, scan, lifecycle.QUEUED)

        progress = _seed_phase7_progress(db, scan, config)
        db.commit()

        _move_state(db, scan, SM.PREFLIGHT, "preflight: probing tool availability")
        snapshot = preflight.build_preflight(db, scan, config)
        events.emit(db, scan.id, events.EVENT_PREFLIGHT, {
            "installed": snapshot["installed"],
            "missing": snapshot["missing"],
            "disabled": snapshot["disabled"],
            "blocked_reasons": snapshot["blocked_reasons"],
        })
        db.commit()

        if preflight.blocked(snapshot):
            _finish_blocked(db, scan, snapshot)
            return

        _move_state(db, scan, SM.RUNNING, "all preflight gates passed; running stages")
        if scan.queue_started_at is not None:
            scan.queue_waited_ms = int(
                (datetime.datetime.utcnow() - scan.queue_started_at).total_seconds() * 1000)
        db.commit()
        stage_rows = _run_stages(db, scan, config, job, progress, snapshot)

        _move_state(db, scan, SM.VALIDATING, "validating candidates with deterministic engine")
        _run_validation(db, scan, config)
        _populate_asset_graph(db, scan)
        _run_finalization(db, scan, progress, stage_rows)

    except ScanCancelled:
        logger.info(f"Scan {scan_id} cancelled.")
        if scan is not None:
            _finish_cancelled(db, scan)
    except Exception as exc:  # a failure must fail the scan, never hang it
        logger.error(f"Phase 7 pipeline failed for scan {scan_id}: {exc}")
        if scan is not None:
            _finish_failed(db, scan, exc)
    finally:
        if db is not None:
            db.close()


# ---------------------------------------------------------------------------
# state / legacy-stage persistence
# ---------------------------------------------------------------------------
def _move_state(db, scan, new_state: str, reason: str = ""):
    SM.validate_transition(scan.state or SM.CREATED, new_state)
    scan.state = new_state
    events.emit_state(db, scan.id, new_state, reason=reason)
    scan.logs = (scan.logs or "") + f"[state:{new_state}] {reason}\n"
    scan.updated_at = datetime.datetime.utcnow()


def _set_legacy(db, scan, stage: str):
    scan.stage = stage
    scan.status = lifecycle.coarse_status(stage)
    scan.updated_at = datetime.datetime.utcnow()


def _seed_phase7_progress(db, scan, config: dict) -> dict:
    planned = plan_tasks(config)
    progress = lifecycle.empty_progress()
    progress["total_tasks"] = len(planned)
    progress["total_tools"] = plan_tool_count(config)
    progress["planned_tasks"] = planned
    progress["execution_platform"] = "phase7"
    _persist_progress(db, scan, progress)
    return progress


# ---------------------------------------------------------------------------
# stage driver
# ---------------------------------------------------------------------------
def _run_stages(db, scan, config, job, progress, snapshot) -> list:
    from database.models import Observation, ScanStage

    stages: list[ScanStage] = []
    state = {"hosts": [scan.target]}
    current_row: ScanStage | None = None
    watermarks: dict[str, int] = {}

    # Phase 10.3: one honest ScanExecution record for this plan execution.
    from app.execution.scheduler import group_plan, execute_batch
    from app.execution.scheduler import max_parallel_tools
    from database.models import ScanExecution

    execution_row = ScanExecution(
        scan_id=scan.id,
        strategy="parallel" if max_parallel_tools(config) > 1 else "sequential",
        max_parallel_tools=max_parallel_tools(config),
        plan=group_plan(config),
        planned_tools=sum(len(g.get("tools") or ()) for g in group_plan(config)),
        status="running",
        started_at=datetime.datetime.utcnow(),
    )
    db.add(execution_row)
    db.flush()

    def _obs_count() -> int:
        return int(db.query(func.max(Observation.id))
                   .filter(Observation.scan_id == scan.id).scalar() or 0)

    def _advance_stage(name: str):
        nonlocal current_row, watermarks
        _check_cancel(scan.id)
        if current_row is not None:
            watermark = watermarks.get(current_row.name, 0)
            _complete_stage(db, scan, current_row, "completed",
                            tests_executed=current_row.tests_executed or 0,
                            observations=max(_obs_count() - watermark, 0))
        scan.stage = _legacy_stage(name)
        scan.status = lifecycle.coarse_status(scan.stage)
        row = ScanStage(
            scan_id=scan.id,
            name=name,
            order=STAGE_ORDER.index(name),
            status="running",
            tools=list(STAGE_TOOLS.get(name, ())),
            started_at=datetime.datetime.utcnow(),
        )
        db.add(row)
        db.flush()
        events.emit_stage(db, scan.id, name, "started")
        current_row = row
        watermarks[name] = _obs_count()
        stages.append(row)
        db.commit()

    try:
        for group in group_plan(config):
            _check_cancel(scan.id)
            stage_name = group["stage"]
            _advance_stage(stage_name)
            progress["completed_tasks"] = (progress.get("completed_tasks") or 0) + 1
            _persist_progress(db, scan, progress)
            db.commit()

            # Run the stage's independent tools (bounded, stage-barrier model).
            results = execute_batch(db, scan, config, job, state, group["tools"])
            for result in results:
                tool = result.get("tool") or ""
                status = result.get("status") or ""
                progress["current_tool"] = tool
                if status in _FAILED_STATES:
                    progress["failed_tasks"] = (progress.get("failed_tasks") or 0) + 1
                    execution_row.started_tools = (execution_row.started_tools or 0) + 1
                    execution_row.failed_tools = (execution_row.failed_tools or 0) + 1
                elif _tool_succeeded(status):
                    progress["completed_tasks"] = (progress.get("completed_tasks") or 0) + 1
                    progress["completed_tools"] = (progress.get("completed_tools") or 0) + 1
                    execution_row.started_tools = (execution_row.started_tools or 0) + 1
                    execution_row.completed_tools = (execution_row.completed_tools or 0) + 1
                elif status == "skipped":
                    execution_row.skipped_tools = (execution_row.skipped_tools or 0) + 1
                if current_row is not None:
                    current_row.tests_executed = (current_row.tests_executed or 0) + 1
                progress["last_tool"] = tool
                _persist_progress(db, scan, progress)
                db.commit()
    except ScanCancelled:
        execution_row.status = "cancelled"
        execution_row.finished_at = datetime.datetime.utcnow()
        db.commit()
        raise
    except Exception as exc:
        logger.error(f"stage execution failed for scan {scan.id}: {exc}")
        execution_row.status = "failed"
        execution_row.finished_at = datetime.datetime.utcnow()
        db.commit()
        raise

    if current_row is not None:
        watermark = watermarks.get(current_row.name, 0)
        _complete_stage(db, scan, current_row, "completed",
                        tests_executed=current_row.tests_executed or 0,
                        observations=max(_obs_count() - watermark, 0))
        db.commit()

    execution_row.status = "completed"
    execution_row.finished_at = datetime.datetime.utcnow()
    if execution_row.started_at is not None:
        execution_row.duration_ms = int(
            (execution_row.finished_at - execution_row.started_at).total_seconds() * 1000)
    db.commit()

    _run_deterministic_assessment(db, scan, config, progress)
    return stages


def _legacy_stage(stage_name: str) -> str:
    from app.orchestration.stages import LEGACY_STAGE
    return LEGACY_STAGE[stage_name]


def _tool_succeeded(status: str) -> bool:
    return status in ("success", "Completed")


def _complete_stage(db, scan, row, status: str, *, tests_executed: int = 0,
                    observations: int = 0, reason: str | None = None):
    row.status = status
    row.reason = reason
    row.tests_executed = tests_executed
    row.observations = observations
    row.finished_at = datetime.datetime.utcnow()
    if row.started_at is not None:
        row.duration_ms = int((row.finished_at - row.started_at).total_seconds() * 1000)
    events.emit_stage(db, scan.id, row.name, status)
    db.flush()


# ---------------------------------------------------------------------------
# deterministic assessment (rules) over persisted observations
# ---------------------------------------------------------------------------
def finding_rules_registry_fingerprint() -> str:
    from app.assess import detection_registry as dr
    return dr.registry_fingerprint()


def _run_deterministic_assessment(db, scan, config, progress):
    from database.models import Vulnerability

    observed = _scan_observations(db, scan.id)
    candidates = finding_rules.evaluate_observations(observed, config=config)
    severity = (config.get("severity") or "all").lower()
    if severity in SEVERITY_THRESHOLD and severity != "all":
        threshold = SEVERITY_THRESHOLD[severity]
        candidates = [
            c for c in candidates
            if SEVERITY_THRESHOLD.get((c.get("severity") or "info").lower(), 99) >= threshold
        ]
    existing = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    existing_keys = {v.dedup_key for v in existing if v.dedup_key}
    candidates = finding_rules.deduplicate(candidates, existing_keys)
    for candidate in candidates:
        _check_cancel(scan.id)
        row = _persisted_finding(scan, candidate, scan.target)
        db.add(row)
        db.flush()
        events.emit_finding_candidate(
            db, scan.id, row.id or 0, candidate.get("title") or row.title or "",
            candidate.get("severity") or row.severity or "",
            candidate.get("rule_id") or row.rule_id or "",
        )
    db.commit()

    findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    scan.security_score = finding_rules.compute_score(
        [{"severity": f.severity or "Info", "state": f.state or "NEW"} for f in findings])
    scan.logs += (
        f"[Assessment] Rule engine applied to {len(observed)} observations "
        f"produced {len(candidates)} evidence-backed finding(s). "
        f"[detection-registry {finding_rules_registry_fingerprint()}]\n"
    )
    db.commit()
    _persist_progress(db, scan, progress)
    db.commit()


# ---------------------------------------------------------------------------
# validation: native engine + auditable validator verdicts
# ---------------------------------------------------------------------------
def _run_validation(db, scan, config):
    from app.assess import engine as assessment_engine
    from database.models import Vulnerability

    try:
        summary = assessment_engine.run_assessment(db, scan, simulation=False, config=config)
        if summary.get("executed"):
            cov = summary.get("coverage") or {}
            scan.logs += (
                f"[Assessment] Phase 5 engine ran {cov.get('tests_executed', 0)}/"
                f"{cov.get('tests_applicable', 0)} applicable test(s); "
                f"coverage {cov.get('coverage_percent')}%; "
                f"{summary.get('findings_confirmed', 0)} confirmed finding(s).\n"
            )
            findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
            scan.security_score = finding_rules.compute_score(
                [{"severity": f.severity or "Info", "state": f.state or "NEW"} for f in findings])
        else:
            scan.logs += f"[Assessment] Phase 5 engine not executed: {summary.get('reason')}.\n"
        db.commit()
    except Exception as exc:  # engine must never fail the scan
        logger.warning(f"Phase 5 assessment engine failed for scan {scan.id}: {exc}")
        scan.logs += f"[Assessment] Phase 5 engine skipped after error: {exc}\n"
        db.commit()

    _record_validations(db, scan)
    _link_observations(db, scan)
    _run_verification(db, scan, config)


def _run_verification(db, scan, config):
    """Phase 10.6: deterministic re-check of every finding over persisted
    observations only.  Never issues a network request; appends ``verifications``
    rows and flips each finding's ``verification_state`` accordingly."""
    from app.assess.verification import run_verification, VERIFICATION_NOT_APPLICABLE

    tally = run_verification(db, scan, config=config)
    lines = tally["states"]
    other = lines.get(VERIFICATION_NOT_APPLICABLE, 0)
    db.commit()
    scan.logs += (
        f"[Verification] {tally['checked']} finding(s) re-checked against "
        f"persisted observations: {lines.get('verified', 0)} verified, "
        f"{lines.get('failed', 0)} failed, {other} no supporting observation. "
        f"[detection-registry {tally['registry']}]\n"
    )
    db.commit()


def _record_validations(db, scan):
    from app.assess import finding_lifecycle as flc
    from database.models import FindingValidation, Observation, Vulnerability
    from app.observations import types as obs_types

    findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    now = datetime.datetime.utcnow()
    for f in findings:
        status = (f.status or flc.STATUS_CANDIDATE).upper()
        if status in ("CONFIRMED", "NEW") or status.startswith("CONFIRM"):
            db.add(FindingValidation(
                scan_id=scan.id,
                finding_id=f.id,
                validator_id=f.rule_id or (f.source_test or "deterministic-rule"),
                status="confirmed",
                condition=f.category,
                reason=f.validation_reason or f.evidence or "confirmed by deterministic validator",
                completed_at=now,
                duration_ms=0,
            ))
            events.emit_finding_verified(
                db, scan.id, f.id or 0, f.title or "", f.severity or "",
                f.rule_id or f.source_test or "",
            )
        elif status == "CANDIDATE":
            db.add(FindingValidation(
                scan_id=scan.id,
                finding_id=f.id,
                validator_id=(f.source_tool or "external_tool"),
                status="rejected",
                condition=f.category,
                reason="external observation surfaced as candidate; no native deterministic validator applied",
                completed_at=now,
                duration_ms=0,
            ))
            events.emit_finding_rejected(
                db, scan.id, f.id or 0, f.title or "",
                f.source_tool or "", "external tool candidate: no native deterministic validator"
            )
    candidate_endpoints = {
        f.endpoint for f in findings
        if (f.status or flc.STATUS_CANDIDATE).upper() == "CANDIDATE"
    }
    for obs in (
        db.query(Observation)
        .filter(Observation.scan_id == scan.id,
                Observation.observation_type == obs_types.OBS_VULNERABILITY)
        .all()
    ):
        if obs.subject in candidate_endpoints:
            continue
        db.add(FindingValidation(
            scan_id=scan.id,
            finding_id=None,
            validator_id=(obs.tool_name or "external_tool"),
            status="rejected",
            condition="external candidate without native confirmation",
            reason="external observation produced no native-confirmed finding",
            observation_id=obs.id,
            completed_at=now,
            duration_ms=0,
        ))
    db.flush()


def _link_observations(db, scan):
    from database.models import FindingObservationLink, Vulnerability

    findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    existing = {
        (lnk.finding_id, lnk.observation_id)
        for lnk in db.query(FindingObservationLink)
        .filter(FindingObservationLink.finding_id.in_([f.id for f in findings])).all()
    }
    for f in findings:
        for oid in (f.evidence_observation_ids or [])[:20]:
            if isinstance(oid, int) and oid > 0 and (f.id, oid) not in existing:
                db.add(FindingObservationLink(finding_id=f.id, observation_id=oid))
                existing.add((f.id, oid))
    db.flush()


def _populate_asset_graph(db, scan):
    """Link every persisted observation onto a real, deduplicated asset graph.

    Phase 9: each observation's ``asset_id`` points at the Asset row it
    measured (its subject host / endpoint).  Assets are created only when a
    real observation references them, and ``parent_asset_id``/``source`` are
    set from real provenance.  Nothing is invented: a subject that is not an
    endpoint (e.g. a DNS fact about the bare target) links to a host asset for
    the scan target.
    """
    from app.orchestration import events
    from database.models import Asset, Observation
    from app.http.fingerprints import host_of

    observations = (
        db.query(Observation)
        .filter(Observation.scan_id == scan.id)
        .order_by(Observation.id.asc())
        .all()
    )
    asset_cache: dict[str, Asset] = {}

    def _find_or_create_asset(asset_type: str, value: str, *, source: str,
                              parent: Asset | None = None) -> Asset:
        key = (asset_type, value)
        if key in asset_cache:
            return asset_cache[key]
        row = (
            db.query(Asset)
            .filter(Asset.project_id == scan.project_id,
                    Asset.type == asset_type, Asset.value == value)
            .first()
        )
        if row is None:
            row = Asset(
                project_id=scan.project_id, type=asset_type, value=value,
                metadata_json={"source": source}, scan_id=scan.id, source=source,
            )
            db.add(row)
            db.flush()
            events.emit_asset_discovered(db, scan.id, row.id, asset_type, value, source)
        if parent is not None and not row.parent_asset_id:
            row.parent_asset_id = parent.id
        asset_cache[key] = row
        return row

    host_root = _find_or_create_asset("host", scan.target, source="scan_target")
    for obs in observations:
        if obs.asset_id:
            continue
        subject = (obs.subject or scan.target)
        if "://" in subject:
            host = host_of(subject) or scan.target
        else:
            host = subject.lower()
        if not host:
            host = scan.target
        host_asset = host_root
        if host.lower() != scan.target.lower():
            host_asset = _find_or_create_asset("host", host, source=obs.tool_name or "probe",
                                               parent=host_root)
        if obs.subject and "://" in obs.subject and host:
            endpoint = _find_or_create_asset("endpoint", subject, source=obs.tool_name or "probe",
                                             parent=host_asset)
            obs.asset_id = endpoint.id
        else:
            obs.asset_id = host_asset.id
    db.commit()


# ---------------------------------------------------------------------------
# finalization: cross-scan tracking, coverage, report, terminal state
# ---------------------------------------------------------------------------
def _run_finalization(db, scan, progress, stage_rows):
    from app.ml import advisory
    from database.models import ScanStage, Vulnerability

    _move_state(db, scan, SM.FINALIZING, "finalizing findings, coverage and report")

    tracking_rows = _track_cross_scan(db, scan)

    confirmed_total = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).count()
    for row in stage_rows:
        matched = db.query(ScanStage).filter(ScanStage.id == row.id).first()
        if matched is not None:
            matched.confirmed_findings = confirmed_total

    ml = advisory.generate(db, scan, tracking_rows=tracking_rows)

    planning = plan_tasks(scan.scan_config or {})
    progress["percent"] = round(
        100.0 * min(progress.get("completed_tasks") or 0, len(planning)) / max(len(planning), 1), 1)
    scan.coverage = lifecycle.compute_coverage(progress)
    scan.updated_at = datetime.datetime.utcnow()
    _persist_progress(db, scan, progress)
    events.emit(db, scan.id, events.EVENT_COVERAGE, {
        "coverage_percent": scan.coverage,
        "completed": progress.get("completed_tasks"),
        "total": progress.get("total_tasks"),
    })
    db.commit()

    _build_report(db, scan, ml)

    failed = progress.get("failed_tasks") or 0
    terminal = SM.COMPLETED_WITH_GAPS if failed else SM.COMPLETED
    _move_state(db, scan, terminal,
                "scan completed" + (f" with {failed} failed task(s)" if failed else ""))
    _finish_terminal(db, scan, terminal)
    events.emit(db, scan.id, events.EVENT_DONE, {"state": scan.state})
    db.commit()


def _track_cross_scan(db, scan):
    from app.assess import tracking
    return tracking.update_cross_scan(db, scan)


def _build_report(db, scan, ml: dict | None):
    from database.models import Report, ToolExecution
    from database.models import ScanStage

    findings = scan_findings(db, scan)
    observations = _scan_observations(db, scan.id)
    findings_payload = [_finding_dict(f) for f in findings]
    observations_payload = [
        {"id": o["id"], "tool": o["tool"], "kind": o["kind"], "subject": o["subject"],
         "data": o["data"], "raw": o["raw"]}
        for o in observations
    ]
    markdown = generate_markdown_report_content(scan, findings, observations, simulation=False)
    sections = _sections_from_markdown(markdown)
    from app.reporting import html_renderer, pdf_writer

    generated_at = (scan.completed_at or datetime.datetime.utcnow()).isoformat() + "Z"
    html = html_renderer.render_html(
        sections,
        title=f"Report - {scan.target}",
        generated_at=generated_at,
        fingerprint="",
    )
    pdf = pdf_writer.render_pdf(
        sections,
        title=f"Assessment Report - {scan.target}",
        generated_at=generated_at,
        fingerprint="",
    )

    executions_payload = [
        {"tool": e.tool, "stage": e.stage, "attempt": e.attempt, "status": e.status,
         "duration_ms": e.duration_ms, "parsed_observations": e.parsed_observations,
         "command": e.command_redacted, "exit_code": e.exit_code,
         "termination_reason": e.termination_reason}
        for e in db.query(ToolExecution).filter(ToolExecution.scan_id == scan.id).all()
    ]
    stages_payload = [
        {"name": s.name, "order": s.order, "status": s.status, "tests_executed": s.tests_executed,
         "observations": s.observations, "confirmed_findings": s.confirmed_findings,
         "duration_ms": s.duration_ms}
        for s in db.query(ScanStage).filter(ScanStage.scan_id == scan.id).all()
    ]

    db.add(Report(
        scan_id=scan.id,
        title=f"Security Assessment Report for {scan.target}",
        markdown_content=markdown,
        json_content={
            "target": scan.target,
            "security_score": scan.security_score,
            "security_coverage": scan.coverage,
            "simulation": False,
            "findings": findings_payload,
            "observations": observations_payload,
            "preflight": (scan.preflight_json or {}),
            "stages": stages_payload,
            "executions": executions_payload,
            "ml_advisory": (ml or {}).get("advisory_json"),
            "coverage": scan.coverage,
            "execution_platform_version": "phase7",
            "execution_trail": {
                "status": scan.status,
                "state": scan.state,
                "total_tasks": (scan.progress or {}).get("total_tasks"),
                "completed_tasks": (scan.progress or {}).get("completed_tasks"),
                "failed_tasks": (scan.progress or {}).get("failed_tasks"),
                "percent": (scan.progress or {}).get("percent"),
                "stages": [s["name"] for s in stages_payload],
                "tools": [e["tool"] for e in executions_payload],
            },
        },
        html_content=html,
        pdf_content=pdf,
    ))
    db.commit()


def _sections_from_markdown(markdown: str) -> list[dict]:
    """Split a report's markdown into (id, title, markdown) section entries.

    Top-level H2 headings become section boundaries; the content before the
    first heading is kept as the opening section.
    """
    sections: list[dict] = []
    current: dict | None = None
    buffer: list[str] = []
    for raw in markdown.split("\n"):
        line = raw.rstrip()
        is_h2 = bool(line.startswith("## "))
        if is_h2 and current is not None and buffer:
            current["markdown"] = "\n".join(buffer).strip()
            sections.append(current)
            buffer = []
        if is_h2:
            title = line[3:].strip()
            current = {"id": _slugify(title), "title": title, "markdown": ""}
        elif current is not None or sections:
            buffer.append(line)
    if current is not None:
        current["markdown"] = "\n".join(buffer).strip()
        sections.append(current)
    if not sections and markdown.strip():
        sections.append({
            "id": "report",
            "title": "Report",
            "markdown": markdown.strip(),
        })
    return [s for s in sections if s["markdown"]]


def _slugify(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "section"


def scan_findings(db, scan):
    from database.models import Vulnerability
    return db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).order_by(
        Vulnerability.id.asc()).all()


# ---------------------------------------------------------------------------
# terminal handling
# ---------------------------------------------------------------------------
def _finish_terminal(db, scan, state: str):
    scan.state = state
    if state == SM.COMPLETED:
        scan.stage = lifecycle.COMPLETED
        scan.status = "Completed"
    elif state == SM.COMPLETED_WITH_GAPS:
        scan.stage = lifecycle.PARTIAL
        scan.status = "Partially Completed"
    elif state == SM.BLOCKED:
        scan.stage = lifecycle.STARTING
        scan.status = "Blocked"
    else:
        scan.stage = lifecycle.FAILED
        scan.status = "Failed"
    if state in (SM.COMPLETED, SM.COMPLETED_WITH_GAPS, SM.BLOCKED, SM.FAILED):
        scan.completed_at = datetime.datetime.utcnow()
    scan.updated_at = datetime.datetime.utcnow()


def _finish_blocked(db, scan, snapshot):
    reasons = snapshot.get("blocked_reasons") or []
    _move_state(db, scan, SM.BLOCKED, "; ".join(reasons) or "preflight blocked the scan")
    scan.error = "; ".join(reasons)[:500]
    _finish_terminal(db, scan, SM.BLOCKED)
    events.emit(db, scan.id, events.EVENT_ERROR, {"reason": reasons})
    db.commit()


def _finish_cancelled(db, scan):
    _move_state(db, scan, SM.CANCELLED, "cancelled by user; remaining stages abandoned")
    scan.stage = lifecycle.CANCELLED
    scan.status = "Cancelled"
    scan.cancelled_at = datetime.datetime.utcnow()
    scan.updated_at = datetime.datetime.utcnow()
    events.emit(db, scan.id, events.EVENT_DONE, {"state": SM.CANCELLED})
    db.commit()


def _finish_failed(db, scan, exc):
    _move_state(db, scan, SM.FAILED, f"pipeline error: {exc}")
    scan.stage = lifecycle.FAILED
    scan.status = "Failed"
    scan.error = str(exc)[:500]
    scan.completed_at = datetime.datetime.utcnow()
    scan.updated_at = datetime.datetime.utcnow()
    events.emit(db, scan.id, events.EVENT_ERROR, {"reason": str(exc)[:500]})
    db.commit()