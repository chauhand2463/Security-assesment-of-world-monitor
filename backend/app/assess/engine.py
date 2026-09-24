"""Scan-time bridge between the database and the Phase 5 assessment engine.

This module is the only place that knows about both the ORM and the pure engine.
It builds an :class:`AssessmentContext` from persisted scan state, runs the
planner, and persists observations, the assessment-test ledger, confirmed
findings and structured evidence.  It is deliberately conservative:

  * it never runs in simulation mode;
  * active (mutating) testing is opt-in via ``config['active_testing']``;
  * every request is scope-guarded against the project's authorized scope;
  * it never fabricates a finding -- only validated candidates are persisted;
  * a failure here degrades the scan to "assessment skipped", never a crash.
"""
from __future__ import annotations

import datetime
import json
import logging

from app.observations.normalize import build_observation, normalize_endpoint

logger = logging.getLogger("cyberagent.assessment")

_MAX_ENDPOINTS = 25
_MAX_REQUESTS = 200


def _scan_user_id(db, scan) -> str | None:
    from database.models import Project

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    return getattr(project, "user_id", None)


def _scope_guard(db, scan):
    from app.core.auth import is_target_in_scope
    from app.http.fingerprints import host_of
    from database.models import Asset, Project

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    assets = db.query(Asset).filter(Asset.project_id == scan.project_id).all()

    def guard(url: str) -> bool:
        host = host_of(url)
        if not host:
            return False
        if host == scan.target:
            return True
        return bool(project and is_target_in_scope(host, project, assets))

    return guard


def _candidate_endpoints(db, scan) -> list[str]:
    """In-scope HTTP endpoints derived from persisted observations and assets.

    Full observed URLs (scheme://host:port/path?query) are preserved so active
    parameter tests have real parameters to work with; asset/target hosts are
    expanded into both schemes.
    """
    from database.models import Asset, Observation

    guard = _scope_guard(db, scan)
    endpoints: list[str] = []

    def add(url: str) -> None:
        candidate = url.split("#", 1)[0]
        if guard(candidate) and candidate not in endpoints:
            endpoints.append(candidate)

    for obs in db.query(Observation).filter(Observation.scan_id == scan.id).all():
        subject = obs.subject or ""
        if subject.startswith("http"):
            add(subject)

    hosts: list[str] = []
    for value in (scan.target,):
        if value and value not in hosts:
            hosts.append(value)
    for asset in db.query(Asset).filter(Asset.project_id == scan.project_id).all():
        if asset.type in ("domain", "ip") and asset.value and asset.value not in hosts:
            hosts.append(asset.value)

    for host in hosts:
        for scheme in ("https", "http"):
            add(f"{scheme}://{host}")
            if len(endpoints) >= _MAX_ENDPOINTS:
                return endpoints
    return endpoints


def _load_observation_dicts(db, scan_id: int) -> list[dict]:
    from database.models import Observation

    rows = db.query(Observation).filter(Observation.scan_id == scan_id).order_by(Observation.id.asc()).all()
    return [
        {
            "id": o.id,
            "observation_type": o.observation_type or o.kind,
            "kind": o.kind,
            "subject": o.subject,
            "data_json": o.data_json or {},
            "response_json": o.response_json,
            "raw_output": o.raw_output or "",
        }
        for o in rows
    ]


def _build_context(db, scan, config: dict, active_testing: bool):
    from app.assess.models import AssessmentContext
    from app.http.client import HttpLimits, SafeHttpClient

    limits = HttpLimits(max_requests_per_scan=_MAX_REQUESTS, active_testing=active_testing)
    guard = _scope_guard(db, scan)
    client = SafeHttpClient(guard, limits, capture_tls=True)
    return AssessmentContext(
        scan_id=scan.id,
        target=scan.target,
        simulation=False,
        active_testing=active_testing,
        user_id=_scan_user_id(db, scan),
        limits=limits,
        scope_guard=guard,
        client=client,
        observations=_load_observation_dicts(db, scan.id),
        endpoints=_candidate_endpoints(db, scan),
        assets=[scan.target],
        auth_identities=dict(config.get("auth_identities") or {}),
        ssrf_validation_url=config.get("ssrf_validation_url"),
        config=config,
        metadata={
            "installed_tools": list(config.get("installed_tools") or []),
            "jwt_tokens": list(config.get("jwt_tokens") or []),
            "jwt_alg_none_accepted": bool(config.get("jwt_alg_none_accepted")),
            "ssrf_token": config.get("ssrf_token"),
            "tools_missing": list(config.get("tools_missing") or []),
        },
    )


def run_assessment(db, scan, simulation: bool = True, config: dict | None = None,
                   user_id: str | None = None) -> dict:
    """Run the Phase 5 engine for ``scan`` and persist its outputs.

    Returns a deterministic summary dict; ``{"executed": False, ...}`` when the
    engine intentionally did not run (simulation or disabled).
    """
    config = dict(config or {})
    if simulation:
        from app.assess import summary as summary_mod

        summary_mod.snapshot(db, scan, config, coverage=None)
        db.commit()
        return {"executed": False, "reason": "simulation mode", "findings_confirmed": 0}
    if config.get("assessment_engine") is False:
        from app.assess import summary as summary_mod

        summary_mod.snapshot(db, scan, config, coverage=None)
        db.commit()
        return {"executed": False, "reason": "assessment engine disabled", "findings_confirmed": 0}

    from app.assess import coverage as coverage_mod
    from app.assess import planner
    from app.assess.registry import default_registry

    active_testing = bool(config.get("active_testing", False))
    registry = default_registry()
    context = _build_context(db, scan, config, active_testing)
    if user_id is None:
        user_id = context.user_id

    assessment_plan, report = planner.plan_and_run(context, registry)

    observation_rows = _persist_observations(db, scan, report, user_id, context.target)
    candidates = planner.confirmed_candidates(report, registry)
    candidates = _drop_existing(db, scan, candidates)
    finding_rows, finding_by_key = _persist_findings(db, scan, candidates, observation_rows, context.target)
    _persist_external_candidates(db, scan)
    _persist_assessment_tests(db, scan, assessment_plan, report, registry, observation_rows, finding_by_key)
    coverage_summary = coverage_mod.summarize(assessment_plan, report, context)
    _persist_tool_result(db, scan, coverage_summary, len(observation_rows))

    from app.assess import summary as summary_mod

    coverage_dict = coverage_summary.to_dict()
    summary_mod.snapshot(db, scan, config, coverage=coverage_dict)
    db.commit()

    return {
        "executed": True,
        "active_testing": active_testing,
        "coverage": coverage_dict,
        "findings_confirmed": coverage_summary.findings_confirmed,
        "statement": coverage_summary.findings_statement,
        "assessment_status": scan.assessment_status,
        "assessment_completeness": scan.assessment_completeness,
        "headline": summary_mod.headline(
            aggregate_counts=summary_mod.aggregate(db, scan),
            coverage=coverage_dict,
            status=scan.assessment_status,
        ),
    }


def _persist_observations(db, scan, report, user_id, target) -> list[dict]:
    from database.models import Observation

    rows: list[dict] = []
    for outcome in report.outcomes:
        for produced in outcome.observations:
            kwargs = build_observation(
                scan_id=scan.id,
                observation_type=produced.observation_type,
                subject=(produced.subject or target)[:255],
                tool_name=produced.tool_name,
                source=produced.source,
                user_id=user_id,
                target=target,
                asset=_host(produced.subject),
                data=produced.data,
                raw_output=produced.raw_output,
                request=produced.request,
                response=produced.response,
                status=produced.status,
                discriminator=produced.discriminator,
            )
            row = Observation(**kwargs)
            db.add(row)
            db.flush()
            _emit_observation_event(db, scan, row)
            rows.append({"id": row.id, "test_id": outcome.test_id, "endpoint": produced.subject,
                         "parameter": (produced.data or {}).get("parameter"), "request": produced.request,
                         "response": produced.response})
    return rows


def _emit_observation_event(db, scan, row) -> None:
    """Emit the phase-9 ``observation.created`` event after real persistence."""
    from app.orchestration import events

    events.emit_observation(db, scan.id, row.id, row.kind, row.subject,
                            row.tool_name or "")


def _drop_existing(db, scan, candidates):
    from database.models import Vulnerability

    existing = {
        v.dedup_key for v in db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        if v.dedup_key
    }
    return [c for c in candidates if c.dedup_key not in existing]


def _persist_findings(db, scan, candidates, observation_rows, target) -> tuple[list, dict]:
    from app.assess import finding_lifecycle as lifecycle
    from app.assess import profile
    from app.assess.evidence import summary as evidence_summary
    from database.models import Vulnerability

    index = _observation_index(observation_rows)
    finding_by_key: dict[str, int] = {}
    rows = []
    now = datetime.datetime.utcnow()
    for candidate in candidates:
        prof = profile.profile_finding(
            category=candidate.category, severity=candidate.severity,
            source_test=candidate.source_test, endpoint=candidate.endpoint,
            source_tool=candidate.source_tool)
        row = Vulnerability(
            scan_id=scan.id,
            title=candidate.title,
            severity=candidate.severity,
            description=candidate.description,
            remediation=candidate.remediation or None,
            cwe=candidate.cwe,
            owasp=candidate.owasp,
            target=candidate.target or target,
            proof_of_concept=candidate.proof_of_concept,
            rule_id=candidate.category,
            dedup_key=candidate.dedup_key,
            confidence=candidate.confidence,
            state="NEW",
            category=candidate.category,
            endpoint=candidate.endpoint,
            http_method=candidate.method,
            parameter=candidate.parameter,
            source_test=candidate.source_test,
            source_tool=candidate.source_tool,
            validation_reason=candidate.actual or "",
            impact=candidate.impact or None,
            status=lifecycle.STATUS_CONFIRMED,
            affected_component=prof["affected_component"],
            impact_details=prof["impact_details"],
            technical_impact=prof["impact_details"].get("technical"),
            business_impact=prof["impact_details"].get("business"),
            remediation_details=prof["remediation_details"],
            references_json=None,
            fingerprint=candidate.dedup_key,
            first_seen=now,
            last_seen=now,
            evidence=evidence_summary(candidate),
            evidence_observation_ids=sorted(
                set(candidate.observation_ids or [])
                | {o["id"] for o in _matching_observations(index, candidate)}
            ),
            created_at=now,
        )
        db.add(row)
        db.flush()
        lifecycle.record_initial(
            db, row, reason=f"validated by {candidate.source_test or 'assessment engine'}")
        rows.append(row)
        finding_by_key[candidate.dedup_key] = row.id
        _persist_evidence(db, row, candidate, index)
    return rows, finding_by_key


_ADAPTER_TOOLS = ("nmap", "nuclei", "httpx", "ffuf", "nikto", "sqlmap", "testssl")


def _persist_external_candidates(db, scan) -> dict:
    """Surface external-tool vulnerability observations as *candidate* findings.

    External adapters run independently of the native engine; their
    ``vulnerability`` observations are real and recorded, but they have not been
    confirmed by a native deterministic validator.  They are therefore persisted
    with lifecycle status ``candidate`` -- never ``confirmed`` -- so the report
    can surface them without overstating them.
    """
    from app.assess import finding_lifecycle as lifecycle
    from app.observations import types
    from database.models import Observation, Vulnerability

    existing = {
        v.dedup_key for v in db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        if v.dedup_key
    }
    rows = (
        db.query(Observation)
        .filter(
            Observation.scan_id == scan.id,
            Observation.observation_type == types.OBS_VULNERABILITY,
        )
        .order_by(Observation.id.asc())
        .all()
    )

    created = 0
    merged = 0
    now = datetime.datetime.utcnow()
    for obs in rows:
        tool = (obs.tool_name or "").lower()
        if tool not in _ADAPTER_TOOLS:
            continue
        data = obs.data_json or {}
        category = data.get("category") or data.get("cwe") or "external_tool"
        subject = (obs.subject or scan.target)
        severity = str(data.get("severity") or "Info").capitalize()
        if severity not in ("Critical", "High", "Medium", "Low", "Info"):
            severity = "Info"
        # Phase 10.7: ONE fingerprint namespace.  External candidates derive
        # their dedup identity from the same ``finding_fingerprint`` function
        # native (confirmed) findings use -- so the same issue reported by
        # nuclei and by the native engine collides instead of living in
        # disjoint key namespaces.  The tool identity is preserved in
        # ``source_tool`` (provenance), never in the identity key.
        from app.http.fingerprints import host_of
        from app.observations.fingerprint import finding_fingerprint

        host = host_of(subject) or scan.target
        dedup_key = finding_fingerprint(category, host, normalize_endpoint(subject), None)
        match = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan.id,
                    Vulnerability.fingerprint == dedup_key)
            .first()
        )
        if match is not None:
            # Cross-tool correlation: the same underlying issue already exists
            # (native-confirmed or earlier candidate).  Merge the real external
            # observation as corroborating evidence instead of duplicating or
            # dropping it; the existing finding's status/history is preserved.
            _merge_external_observation(db, scan, match, obs, tool)
            existing.add(dedup_key)
            merged += 1
            continue
        if dedup_key in existing:
            continue
        description = (
            f"External tool `{tool}` reported a potential "
            f"`{data.get('name') or data.get('template') or category}` issue. "
            "This is a candidate finding surfaced from the external observation and "
            "has not been re-validated by the native deterministic engine."
        )
        row = Vulnerability(
            scan_id=scan.id,
            title=f"{tool} candidate: {data.get('name') or data.get('template') or category}".strip(),
            severity=severity,
            description=description,
            cwe=str(category) if category.startswith("CWE") else None,
            target=obs.target or scan.target,
            dedup_key=dedup_key,
            confidence="MEDIUM",
            state="NEW",
            category=str(category),
            endpoint=subject,
            source_tool=tool,
            validation_reason="external observation; not re-validated by native engine",
            status=lifecycle.STATUS_CANDIDATE,
            fingerprint=dedup_key,
            first_seen=now,
            last_seen=now,
            created_at=now,
        )
        db.add(row)
        db.flush()
        existing.add(dedup_key)
        lifecycle.record_initial(db, row, reason=f"candidate from external tool {tool}")
        created += 1
    return {"created": created, "merged": merged}


def _merge_external_observation(db, scan, finding, obs, tool: str) -> None:
    """Corroborate an existing finding with a real external observation.

    Phase 10.7 cross-tool correlation: when an external adapter (e.g. nuclei)
    reports the same issue that a native-confirmed finding (or an earlier
    candidate) already represents, we attach the observation as evidence and
    list the tool as a corroborating source.  The finding's lifecycle status,
    history and verdict are NEVER rewritten.
    """
    from app.assess import finding_lifecycle as lifecycle
    from app.assess import profile
    from app.assess.evidence import summary as evidence_summary
    from database.models import FindingEvidence, FindingObservationLink

    now = datetime.datetime.utcnow()
    obs_ids = list(finding.evidence_observation_ids or [])
    if obs.id not in obs_ids:
        obs_ids.append(obs.id)
        finding.evidence_observation_ids = obs_ids
    existing_link = (
        db.query(FindingObservationLink)
        .filter(FindingObservationLink.finding_id == finding.id,
                FindingObservationLink.observation_id == obs.id)
        .first()
    )
    if existing_link is None:
        db.add(FindingObservationLink(finding_id=finding.id, observation_id=obs.id))
    # Record the corroborating tool without changing the existing identity.
    sources = [s.strip() for s in (finding.source_tool or "").split(",") if s.strip()]
    if tool not in sources:
        sources.append(tool)
        finding.source_tool = ", ".join(sources)
    finding.last_seen = now
    finding.occurrence_count = (finding.occurrence_count or 1) + 1
    db.flush()


def _persist_evidence(db, finding, candidate, index) -> None:
    from app.assess.evidence import evidence_to_kwargs
    from app.assess.models import EvidenceData
    from database.models import FindingEvidence

    matches = _matching_observations(index, candidate)
    if matches:
        for match in matches[:3]:
            evidence = EvidenceData(
                evidence_type="comparison", expected=candidate.expected, actual=candidate.actual,
                security_boundary=candidate.security_boundary, request=match.get("request"),
                response=match.get("response"),
            )
            db.add(FindingEvidence(**evidence_to_kwargs(finding.id, evidence, match["id"])))
    else:
        evidence = EvidenceData(
            evidence_type="comparison", expected=candidate.expected, actual=candidate.actual,
            security_boundary=candidate.security_boundary,
        )
        db.add(FindingEvidence(**evidence_to_kwargs(finding.id, evidence, None)))


def _observation_index(rows):
    index: dict[tuple[str, str | None, str | None], dict] = {}
    for row in rows:
        key = (normalize_endpoint(row.get("endpoint") or ""), row.get("parameter"), row.get("test_id"))
        index.setdefault(key, row)
    return index


def _matching_observations(index, candidate):
    endpoint = normalize_endpoint(candidate.endpoint)
    matches = []
    for key, row in index.items():
        if key[0] != endpoint:
            continue
        if candidate.parameter and key[1] and key[1] != candidate.parameter:
            continue
        matches.append(row)
    return matches


def _persist_assessment_tests(db, scan, assessment_plan, report, registry, observation_rows, finding_by_key):
    from database.models import AssessmentTest

    produced_by_test: dict[str, list[int]] = {}
    endpoints_by_test: dict[str, str | None] = {}
    for row in observation_rows:
        produced_by_test.setdefault(row["test_id"], []).append(row["id"])
        if endpoints_by_test.get(row["test_id"]) is None:
            subject = (row.get("subject") or "").strip()
            if subject.startswith("http"):
                from app.observations.normalize import normalize_endpoint

                endpoints_by_test[row["test_id"]] = normalize_endpoint(subject)

    now = datetime.datetime.utcnow()
    for planned, outcome in zip(assessment_plan.planned, report.outcomes):
        test = registry.get(planned.test_id)
        finding_ids = [
            finding_by_key[c.dedup_key]
            for c in outcome.candidates
            if c.dedup_key in finding_by_key
        ]
        row = AssessmentTest(
            scan_id=scan.id,
            test_id=planned.test_id,
            name=(test.name if test else planned.test_id),
            category=planned.category,
            status=outcome.status,
            reason=outcome.reason or planned.reason or "",
            target=scan.target,
            active=planned.active,
            endpoint=endpoints_by_test.get(planned.test_id),
            required_observations=list(getattr(test, "required_observations", ()) or []),
            required_capabilities=list(getattr(test, "required_capabilities", ()) or []),
            observation_ids=produced_by_test.get(planned.test_id, []),
            finding_ids=finding_ids,
            started_at=now,
            completed_at=now,
        )
        db.add(row)
        db.flush()
        from app.orchestration import events

        events.emit_assessment_item(db, scan.id, row.id, row.test_id, row.name,
                                    row.category, row.status, row.endpoint)


def _persist_tool_result(db, scan, coverage_summary, observation_count: int):
    from database.models import ToolResult

    db.add(ToolResult(
        scan_id=scan.id,
        tool_name="native_assessment",
        status="Completed",
        raw_output=json.dumps(coverage_summary.to_dict(), default=str),
        parsed_observations=observation_count,
        completed_at=datetime.datetime.utcnow(),
    ))


def _host(url: str | None) -> str | None:
    if not url:
        return None
    from app.http.fingerprints import host_of

    return host_of(url) or None


__all__ = ["run_assessment"]
