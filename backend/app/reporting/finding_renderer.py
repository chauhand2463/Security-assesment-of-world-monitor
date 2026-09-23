"""Assess per-finding rendering for the report (Phase 6).

A rendered finding is the auditable entity: lifecycle status, deterministic
CVSS-derived metadata (with an explicit consistency result), affected component,
impact, remediation, proof-of-concept, evidence references (with integrity
hashes), and the immutable status history.  Nothing here is fabricated.
"""
from __future__ import annotations

from typing import Any

from app.assess import finding_lifecycle as lifecycle
from app.assess import profile
from app.assess.cvss import CvssValidationError, validate_cvss
from app.assess.poc import build_poc
from app.reporting.redaction import safe_text


def cvss_block(db, finding) -> dict[str, Any]:
    """Expose stored CVSS metadata plus a deterministic consistency result."""
    stored = {
        "score": getattr(finding, "cvss_score", None),
        "vector": getattr(finding, "cvss_vector", None),
        "version": getattr(finding, "cvss_version", None),
    }
    legacy = getattr(finding, "cvss", None)
    if stored["vector"]:
        try:
            validate_cvss(vector=stored.get("vector"), score=stored.get("score"),
                          severity=finding.severity)
            consistency = {"status": "consistent", "note": "score, vector and severity agree."}
        except CvssValidationError as exc:
            consistency = {"status": "inconsistent", "note": str(exc)}
    elif legacy is not None and finding.severity:
        from app.assess.cvss import severity_for_score

        band = severity_for_score(float(legacy))
        consistency = {
            "status": "consistent" if band == (finding.severity or "").capitalize() else "inconsistent",
            "note": f"legacy numeric score {legacy} vs declared severity {finding.severity}",
        }
    else:
        consistency = {"status": "n/a", "note": "no CVSS vector or legacy score stored."}
    return {**stored, "consistency": consistency}


def history_entries(db, finding) -> list[dict]:
    from database.models import FindingStatusHistory

    rows = (
        db.query(FindingStatusHistory)
        .filter(FindingStatusHistory.finding_id == finding.id)
        .order_by(FindingStatusHistory.created_at.asc(), FindingStatusHistory.id.asc())
        .all()
    )
    return [
        {
            "from_status": h.from_status,
            "to_status": h.to_status,
            "actor": h.actor,
            "reason": safe_text(h.reason),
            "created_at": (h.created_at.isoformat() + "Z") if h.created_at else None,
        }
        for h in rows
    ]


def _verification_entries(db, finding) -> list[dict]:
    from database.models import Verification

    rows = (
        db.query(Verification)
        .filter(Verification.finding_id == finding.id)
        .order_by(Verification.id.asc())
        .all()
    )
    return [
        {
            "id": v.id,
            "method": v.method,
            "status": v.status,
            "rule_id": v.rule_id,
            "condition": v.condition,
            "reason": safe_text(v.reason),
            "observation_ids": v.observation_ids or [],
            "completed_at": (v.completed_at.isoformat() + "Z") if v.completed_at else None,
        }
        for v in rows
    ]


def render_finding(db, finding) -> dict[str, Any]:
    status = finding.status or lifecycle.STATUS_CONFIRMED
    out = {
        "id": finding.id,
        "status": status,
        # Epistemic provenance (Phase 8.5): a confirmed finding passed a
        # deterministic validator (validated); a candidate is a real,
        # evidence-backed observation that has not yet been validated.  Nothing
        # from the ML advisory is ever represented as a finding.
        "provenance": "validated" if status == lifecycle.STATUS_CONFIRMED else "observed",
        # Phase 10.6: deterministic re-check verdict over persisted observations.
        "verification_state": finding.verification_state or "unverified",
        "severity": finding.severity,
        "title": safe_text(finding.title),
        "description": safe_text(finding.description),
        "rule_id": finding.rule_id,
        "category": finding.category,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter": finding.parameter,
        "affected_component": finding.affected_component or profile.resolve_component(
            category=finding.category, source_test=finding.source_test,
            endpoint=finding.endpoint, source_tool=finding.source_tool),
        "cvss": cvss_block(db, finding),
        "impact": {
            "technical": safe_text(finding.technical_impact),
            "business": safe_text(finding.business_impact),
            "details": (finding.impact_details or {}) if isinstance(finding.impact_details, dict) else {},
        },
        "remediation": safe_text(finding.remediation),
        "remediation_details": (finding.remediation_details or {})
        if isinstance(finding.remediation_details, dict) else {},
        "references": (finding.references_json or []) if isinstance(finding.references_json, list) else [],
        "evidence_ids": [e.id for e in finding.evidence_records],
        "verifications": _verification_entries(db, finding),
        "history": history_entries(db, finding),
        "first_seen": (finding.first_seen.isoformat() + "Z") if finding.first_seen else None,
        "last_seen": (finding.last_seen.isoformat() + "Z") if finding.last_seen else None,
        "fingerprint": finding.fingerprint or finding.dedup_key,
    }
    return out


def finding_to_markdown(db, finding) -> str:
    r = render_finding(db, finding)
    cvss = r["cvss"]
    vector_line = f"`{cvss['vector']}`" if cvss.get("vector") else "*none stored*"
    score_line = f"{cvss['score']} ({cvss['consistency']['status']})" if cvss.get("score") is not None else "*none stored*"
    lines = [
        f"### F-{r['id']} ({r['status']}) — {r['title']}",
        "",
        f"- **Provenance:** {r['provenance']}"
        + (" (deterministic validator)" if r["provenance"] == "validated" else " (evidence-backed observation, awaiting validation)"),
        f"- **Severity:** {r['severity']}   **Component:** {r['affected_component']}",
        f"- **Endpoint:** `{r['endpoint'] or 'n/a'}` {r['http_method'] or ''}".rstrip(),
        f"- **CVSS:** version {cvss['version'] or 'n/a'} | score {score_line} | vector {vector_line}",
        f"- **Category/rule:** {r['category'] or 'n/a'} (`{r['rule_id'] or 'n/a'}`)",
        "",
        "**Impact (technical):** " + (r["impact"]["technical"] or "*none*"),
        "**Impact (business):** " + (r["impact"]["business"] or "*none*"),
        "**Remediation:** " + (r["remediation"] or "*see remediation_details*"),
        "",
        "**Validation:**",
        f"- reason: `{safe_text(finding.validation_reason) or 'n/a'}`",
        f"- evidence record ids: {', '.join(str(i) for i in r['evidence_ids']) or 'none'}",
        f"- fingerprint: `{r['fingerprint'] or 'n/a'}`",
        "",
        "**Verification (Phase 10.6):**",
        f"- state: `{r['verification_state']}`",
    ]
    for v in r["verifications"]:
        lines.append(
            f"- `{v['status']}` via `{v['method']}` ({v['rule_id'] or 'n/a'}) "
            f"over obs {v['observation_ids'] or []}: {v['reason'] or ''}"
        )
    lines.append("")
    lines.append("**History:**")
    for entry in r["history"]:
        lines.append(
            f"- `{entry['from_status']} -> {entry['to_status']}` by `{entry['actor']}` "
            f"({entry['created_at'] or 'n/a'}): {entry['reason'] or ''}"
        )
    if finding.id:
        from app.reporting.evidence_renderer import evidence_block_markdown

        lines.append("")
        lines.append("**PoC:**")
        lines.append("```")
        poc = build_poc(db, finding)
        lines.append(f"METHOD {poc['request']['method']} {poc['request']['endpoint']}")
        lines.append("expected  : " + (poc["expected_behavior"] or "")[:300])
        lines.append("observed  : " + (poc["observed_behavior"] or "")[:300])
        lines.append("validation: " + (str(poc["validation_logic"]) or "")[:300])
        lines.append("```")
        lines.extend(evidence_block_markdown(db, finding))
    return "\n".join(lines)


__all__ = ["cvss_block", "evidence_block_markdown", "finding_to_markdown", "history_entries", "render_finding"]