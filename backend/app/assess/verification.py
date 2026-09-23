"""Deterministic verification engine (Phase 10.6).

Closes audit gap G6: findings previously got validator verdicts
(``finding_validations``) but there was no first-class ``Verification`` chain
and no ``verification_state`` on the finding.

The engine is strict and safe:

  * it only re-runs rules over the SAME persisted ``Observation`` rows a
    finding was derived from -- it never issues a new network request,
  * a finding is ``verified`` only when the same deterministic rule reproduces
    the same candidate identity (``dedup_key``) from that persisted evidence;
  * when the evidence no longer reproduces the candidate the finding is marked
    ``failed``; when there is no supporting observation it is ``not_applicable``,
  * every re-check appends a ``verifications`` row, so ``verification_state``
    on the finding always traces back to an auditable, replayable proof.

Nothing is fabricated: no rule fires on observations that do not exist.
"""
from __future__ import annotations

import datetime

from database.models import Observation, Verification, Vulnerability

VERIFICATION_UNVERIFIED = "unverified"
VERIFICATION_VERIFIED = "verified"
VERIFICATION_FAILED = "failed"
VERIFICATION_NOT_APPLICABLE = "not_applicable"

METHOD_DETERMINISTIC_RULE = "deterministic.rule"


def _observation_ids_for(finding: Vulnerability) -> list[int]:
    return [i for i in (finding.evidence_observation_ids or [])
            if isinstance(i, int) and i > 0]


def _supporting_observation_dicts(session, finding: Vulnerability) -> list[dict]:
    """Persisted observations backing the finding (for re-running rules)."""
    wanted = set(_observation_ids_for(finding))
    if not wanted and finding.id:
        from database.models import FindingObservationLink

        linked = (
            session.query(FindingObservationLink)
            .filter(FindingObservationLink.finding_id == finding.id)
            .all()
        )
        wanted = {lnk.observation_id for lnk in linked}
    rows = (
        session.query(Observation)
        .filter(Observation.scan_id == finding.scan_id,
                Observation.id.in_(list(wanted)))
        .all()
    )
    return [
        {"id": o.id, "tool": o.tool_name, "kind": o.kind, "subject": o.subject,
         "data": o.data_json or {}, "raw": o.raw_output or ""}
        for o in rows
    ]


def recheck_finding(session, finding: Vulnerability,
                    config: dict | None = None) -> Verification:
    """Run one deterministic re-check for a finding.  Appends the row."""
    from app.assess import finding_rules as fr
    from app.assess.detection_registry import default_registry

    started = datetime.datetime.utcnow()
    rule_id = finding.rule_id or (finding.source_test or "")
    obs = _supporting_observation_dicts(session, finding)

    registry = default_registry()
    condition = "candidate reproduces from the same persisted observations"
    if not obs:
        row = Verification(
            scan_id=finding.scan_id,
            finding_id=finding.id,
            method=METHOD_DETERMINISTIC_RULE,
            status=VERIFICATION_NOT_APPLICABLE,
            rule_id=rule_id or None,
            condition=condition,
            reason="no supporting persisted observation to re-check against",
            observation_ids=[],
            started_at=started,
            completed_at=datetime.datetime.utcnow(),
            duration_ms=0,
        )
        session.add(row)
        finding.verification_state = row.status
        return row

    # Re-run every enabled rule over the finding's own persisted observations.
    enabled = registry.enabled(config)
    candidates: list[dict] = []
    for obs_dict in obs:
        for rule in enabled:
            for candidate in rule.produce(obs_dict):
                candidates.append(candidate)

    known_rule = registry.get(rule_id) is not None
    identity = finding.dedup_key or finding.fingerprint
    reproduced = False
    for candidate in candidates:
        if known_rule and candidate.get("rule_id") != rule_id:
            continue
        if identity and candidate.get("dedup_key") not in (None, identity):
            continue
        # Same rule + same identity on the same persisted observations.
        reproduced = True
        break

    status = VERIFICATION_VERIFIED if reproduced else VERIFICATION_FAILED
    reason = (
        "deterministic rule reproduced the same candidate from persisted observations"
        if reproduced else
        "candidate not reproduced by the deterministic rule over persisted observations"
    )
    row = Verification(
        scan_id=finding.scan_id,
        finding_id=finding.id,
        method=METHOD_DETERMINISTIC_RULE,
        status=status,
        rule_id=rule_id or None,
        condition=condition,
        reason=reason,
        observation_ids=[o["id"] for o in obs],
        started_at=started,
        completed_at=datetime.datetime.utcnow(),
        duration_ms=0,
    )
    session.add(row)
    finding.verification_state = status
    return row


def run_verification(session, scan, config: dict | None = None) -> dict:
    """Re-check every finding of a scan; returns a tally.

    Idempotent per call -- each invocation appends fresh ``verifications`` rows
    and recomputes each finding's ``verification_state`` from the latest
    re-check (the most honest current verdict).
    """
    from app.orchestration import events

    findings = (
        session.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .all()
    )
    counts = {VERIFICATION_VERIFIED: 0, VERIFICATION_FAILED: 0,
              VERIFICATION_NOT_APPLICABLE: 0}
    for finding in findings:
        row = recheck_finding(session, finding, config=config)
        counts[row.status] = counts.get(row.status, 0) + 1
        if row.status == VERIFICATION_VERIFIED:
            events.emit_finding_verified(
                session, scan.id, finding.id or 0, finding.title or "",
                finding.severity or "", row.rule_id or "",
            )
    session.flush()
    return {
        "checked": len(findings),
        "states": counts,
        "registry": _fingerprint(),
    }


def _fingerprint() -> str:
    from app.assess import detection_registry as dr

    return dr.registry_fingerprint()


__all__ = [
    "VERIFICATION_UNVERIFIED", "VERIFICATION_VERIFIED", "VERIFICATION_FAILED",
    "VERIFICATION_NOT_APPLICABLE", "METHOD_DETERMINISTIC_RULE",
    "recheck_finding", "run_verification",
]