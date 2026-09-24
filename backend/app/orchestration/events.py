"""Typed, append-only scan event stream (Phase 7).

The pipeline emits a ScanEvent row for every substantive thing that really
happened: state transitions, stage lifecycle, tool start/finish/skip, preflight
outcomes, coverage/progress changes, findings and their validations, and the
terminal resolution.  Rows are id-ordered with a per-scan ``seq`` so a client
can replay the stream from any cursor (``/scans/{id}/typed-events``).

Nothing invents events: an emit is only called after the described artifact was
persisted by the caller.
"""
from __future__ import annotations

import threading

from database.models import ScanEvent

# Per-scan in-memory seq counters are necessary under parallelism: with
# multiple worker threads emitting events (Phase 10.3), MAX(seq)+1 computed
# from the database races -- two workers could claim the same seq before
# either commits.  A module-level lock serializes allocation per scan, seeded
# lazily from the highest committed seq so replays stay monotonic and unique.
_seq_counters: dict[int, int] = {}
_seq_lock = threading.Lock()

EVENT_STATE = "state"
EVENT_STAGE = "stage"
EVENT_TOOL = "tool"
EVENT_PREFLIGHT = "preflight"
EVENT_PROGRESS = "progress"
EVENT_COVERAGE = "coverage"
EVENT_FINDING = "finding"
EVENT_VALIDATION = "validation"
EVENT_DONE = "done"
EVENT_ERROR = "error"

# Phase 9 granular, evidence-chain event types (extend, never replace).
EVENT_ASSET = "asset.discovered"
EVENT_OBSERVATION = "observation.created"
EVENT_FINDING_CANDIDATE = "finding.candidate"
EVENT_FINDING_VERIFIED = "finding.verified"
EVENT_FINDING_REJECTED = "finding.rejected"

# Phase 12 surface + assessment-program events (additive, typed-ledger only).
EVENT_ENDPOINT = "endpoint.discovered"
EVENT_PARAMETER = "parameter.discovered"
EVENT_ASSESSMENT = "assessment.item"

KNOWN_EVENT_TYPES = frozenset({
    EVENT_STATE, EVENT_STAGE, EVENT_TOOL, EVENT_PREFLIGHT, EVENT_PROGRESS,
    EVENT_COVERAGE, EVENT_FINDING, EVENT_VALIDATION, EVENT_DONE, EVENT_ERROR,
    EVENT_ASSET, EVENT_OBSERVATION,
    EVENT_FINDING_CANDIDATE, EVENT_FINDING_VERIFIED, EVENT_FINDING_REJECTED,
    EVENT_ENDPOINT, EVENT_PARAMETER, EVENT_ASSESSMENT,
})


def next_seq(db, scan_id: int) -> int:
    with _seq_lock:
        nxt = _seq_counters.get(scan_id)
        if nxt is None:
            from sqlalchemy import func

            current = (
                db.query(func.max(ScanEvent.seq))
                .filter(ScanEvent.scan_id == scan_id)
                .scalar()
            )
            nxt = int(current or 0)
        nxt += 1
        _seq_counters[scan_id] = nxt
        return nxt


def emit(db, scan_id: int, event_type: str, data: dict | None = None) -> int:
    """Append one event (caller commits).  Returns the row id."""
    if event_type not in KNOWN_EVENT_TYPES:
        raise ValueError(f"unknown scan event type: {event_type!r}")
    event = ScanEvent(
        scan_id=scan_id,
        event_type=event_type,
        data=data or {},
        seq=next_seq(db, scan_id),
    )
    db.add(event)
    db.flush()
    return event.id


def emit_state(db, scan_id: int, state: str, reason: str = "") -> int:
    return emit(db, scan_id, EVENT_STATE, {
        "state": state,
        "reason": reason,
    })


def emit_stage(db, scan_id: int, name: str, status: str,
               reason: str | None = None) -> int:
    return emit(db, scan_id, EVENT_STAGE, {
        "stage": name,
        "status": status,
        "reason": reason or "",
    })


def emit_tool(db, scan_id: int, tool: str, status: str,
              stage: str | None = None, attempt: int = 1,
              detail: dict | None = None) -> int:
    data = {"tool": tool, "status": status, "attempt": attempt}
    if stage:
        data["stage"] = stage
    if detail:
        data.update(detail)
    return emit(db, scan_id, EVENT_TOOL, data)


def emit_finding(db, scan_id: int, finding_id: int, title: str,
                 severity: str, status: str, fingerprint: str | None = None) -> int:
    return emit(db, scan_id, EVENT_FINDING, {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "status": status,
        "fingerprint": fingerprint,
    })


def emit_validation(db, scan_id: int, finding_id: int | None,
                    validator_id: str, status: str, reason: str = "") -> int:
    return emit(db, scan_id, EVENT_VALIDATION, {
        "finding_id": finding_id,
        "validator_id": validator_id,
        "status": status,
        "reason": reason,
    })


def emit_asset_discovered(db, scan_id: int, asset_id: int | None, asset_type: str,
                          value: str, source: str = "") -> int:
    """Emit after an asset row was persisted (``asset.discovered``)."""
    return emit(db, scan_id, EVENT_ASSET, {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "value": value,
        "source": source,
    })


def emit_observation(db, scan_id: int, observation_id: int, kind: str,
                     subject: str, tool: str) -> int:
    """Emit after an observation row was persisted (``observation.created``)."""
    return emit(db, scan_id, EVENT_OBSERVATION, {
        "observation_id": observation_id,
        "kind": kind,
        "subject": subject,
        "tool": tool,
    })


def emit_finding_candidate(db, scan_id: int, finding_id: int, title: str,
                           severity: str, rule_id: str = "") -> int:
    return emit(db, scan_id, EVENT_FINDING_CANDIDATE, {
        "id": finding_id, "title": title, "severity": severity,
        "rule_id": rule_id,
    })


def emit_finding_verified(db, scan_id: int, finding_id: int, title: str,
                          severity: str, validator_id: str = "") -> int:
    return emit(db, scan_id, EVENT_FINDING_VERIFIED, {
        "id": finding_id, "title": title, "severity": severity,
        "validator_id": validator_id,
    })


def emit_finding_rejected(db, scan_id: int, finding_id: int | None,
                          title: str = "", validator_id: str = "",
                          reason: str = "") -> int:
    return emit(db, scan_id, EVENT_FINDING_REJECTED, {
        "id": finding_id, "title": title, "validator_id": validator_id,
        "reason": reason,
    })


def emit_endpoint_discovered(db, scan_id: int, observation_id: int, url: str,
                             kind: str = "", source: str = "") -> int:
    """Emit after an endpoint-surface observation row was persisted."""
    return emit(db, scan_id, EVENT_ENDPOINT, {
        "observation_id": observation_id,
        "url": url,
        "kind": kind,
        "source": source,
    })


def emit_parameter_discovered(db, scan_id: int, observation_id: int, url: str,
                              parameter: str, source: str = "") -> int:
    """Emit after a parameter-surface observation row was persisted."""
    return emit(db, scan_id, EVENT_PARAMETER, {
        "observation_id": observation_id,
        "url": url,
        "parameter": parameter,
        "source": source,
    })


def emit_assessment_item(db, scan_id: int, assessment_test_id: int, test_id: str,
                         name: str, category: str, status: str,
                         endpoint: str | None = None) -> int:
    """Emit after an assessment-test row was persisted/updated (after a run)."""
    data = {"assessment_test_id": assessment_test_id, "test_id": test_id,
            "name": name, "category": category, "status": status}
    if endpoint:
        data["endpoint"] = endpoint
    return emit(db, scan_id, EVENT_ASSESSMENT, data)


def replay(db, scan_id: int, cursor: int = 0, limit: int = 500) -> list[dict]:
    """Replay persisted events after ``cursor`` (exclusive by event id)."""
    rows = (
        db.query(ScanEvent)
        .filter(ScanEvent.scan_id == scan_id, ScanEvent.id > cursor)
        .order_by(ScanEvent.id.asc())
        .limit(limit)
        .all()
    )
    last = rows[-1].id if rows else cursor
    return {
        "cursor": last,
        "has_more": len(rows) == limit,
        "events": [
            {
                "id": e.id,
                "seq": e.seq,
                "type": e.event_type,
                "data": e.data or {},
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in rows
        ],
    }


__all__ = [
    "emit", "emit_state", "emit_stage", "emit_tool", "emit_finding",
    "emit_validation", "emit_asset_discovered", "emit_observation",
    "emit_finding_candidate", "emit_finding_verified", "emit_finding_rejected",
    "emit_endpoint_discovered", "emit_parameter_discovered",
    "emit_assessment_item",
    "replay", "next_seq",
    "EVENT_STATE", "EVENT_STAGE", "EVENT_TOOL", "EVENT_PREFLIGHT",
    "EVENT_PROGRESS", "EVENT_COVERAGE", "EVENT_FINDING", "EVENT_VALIDATION",
    "EVENT_DONE", "EVENT_ERROR",
    "EVENT_ASSET", "EVENT_OBSERVATION",
    "EVENT_FINDING_CANDIDATE", "EVENT_FINDING_VERIFIED", "EVENT_FINDING_REJECTED",
    "EVENT_ENDPOINT", "EVENT_PARAMETER", "EVENT_ASSESSMENT",
]