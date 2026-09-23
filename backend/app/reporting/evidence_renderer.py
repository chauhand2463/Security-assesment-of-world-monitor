"""Evidence rendering + integrity checks (Phase 6).

Every evidence record is rendered with its integrity hashes and bounded-capture
metadata, and the stored hash is re-verified against the stored payload so
accidental mutation is detectable in the report itself.
"""
from __future__ import annotations

from typing import Any

from app.assess.evidence import verify_evidence_integrity


def render_evidence(db, finding) -> list[dict[str, Any]]:
    from database.models import FindingEvidence

    rows = (
        db.query(FindingEvidence)
        .filter(FindingEvidence.finding_id == finding.id)
        .order_by(FindingEvidence.id.asc())
        .all()
    )
    out = []
    for e in rows:
        integrity = verify_evidence_integrity(e)
        provenance = _observation_provenance(db, e.observation_id)
        out.append({
            "evidence_id": e.id,
            "finding_id": finding.id,
            "observation_id": e.observation_id,
            "evidence_type": e.evidence_type,
            "expected": e.expected,
            "actual": e.actual,
            "security_boundary": e.security_boundary,
            "redaction_status": e.redaction_status,
            "request_hash": e.request_hash,
            "response_hash": e.response_hash,
            "original_size": e.original_size,
            "captured_size": e.captured_size,
            "truncated": e.truncated,
            "integrity": integrity,
            "provenance": provenance,
        })
    return out


def _observation_provenance(db, observation_id: int | None) -> dict | None:
    """Phase 10.4: the real tool-execution that produced the evidence observation.

    NULL provenance is honest: the observation has no ToolExecution row (e.g.
    Phase 5 engine-native HTTP evidence), which means lineage is simply absent,
    never invented.
    """
    if not observation_id:
        return None
    from database.models import Observation, ToolExecution

    obs = db.query(Observation).filter(Observation.id == observation_id).first()
    if obs is None:
        return None
    ex = None
    if obs.tool_execution_id:
        ex = db.query(ToolExecution).filter(ToolExecution.id == obs.tool_execution_id).first()
    if ex is None:
        return {
            "execution_id": None,
            "tool": obs.tool_name,
            "status": obs.status or "observed",
        }
    return {
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
    }


def evidence_block_markdown(db, finding) -> list[str]:
    evidence = render_evidence(db, finding)
    if not evidence:
        return []
    lines = ["", "**Evidence (integrity-verified):**", ""]
    lines.append("| # | type | boundary | req-hash | resp-hash | trunc | integrity |")
    lines.append("|---|------|----------|----------|-----------|-------|-----------|")
    for e in evidence:
        ok = "ok" if (e["integrity"]["request_ok"] and e["integrity"]["response_ok"]) else "MISMATCH"
        lines.append(
            f"| {e['evidence_id']} | {e['evidence_type']} | "
            f"{str(e['security_boundary'] or '')[:24]} | "
            f"{(e['request_hash'] or '-')[:10]} | {(e['response_hash'] or '-')[:10]} | "
            f"{e['truncated'] or '-'} | {ok} |"
        )
    return lines


def evidence_markdown_section(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No structured evidence records to display."
    lines = [
        "| evidence_id | finding_id | type | integrity |",
        "|-------------|------------|------|-----------|",
    ]
    for e in rows:
        ok = e.get("integrity")
        verdict = "ok" if ok and ok.get("request_ok") and ok.get("response_ok") else "MISMATCH"
        lines.append(f"| {e['evidence_id']} | F-{e['finding_id']} | {e['evidence_type']} | {verdict} |")
    return "\n".join(lines)


__all__ = ["evidence_block_markdown", "evidence_markdown_section", "render_evidence"]