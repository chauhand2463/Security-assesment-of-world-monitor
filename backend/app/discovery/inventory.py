"""Phase 12 surface inventory façade (real persisted observations only).

Aggregates everything known about a scan's *observed* attack surface into the
shape consumed by the API and the frontend.  Nothing here invents an endpoint,
a parameter, a host or an asset: each item traces back to persisted
``Observation`` / ``Asset`` rows.  Redaction holds: parameter values and
credential material are never surfaced.
"""
from __future__ import annotations

import datetime
from urllib.parse import urlsplit

from app.discovery.parameters import parameter_inventory
from app.observations.normalize import normalize_endpoint

_NON_INVENTORY_KINDS = {"endpoint_out_of_scope", "wm_not_configured"}

_ASSESSED_TEST_STATUSES = ("executed", "validated", "failed")


def _default_port(scheme: str) -> int:
    """Deterministic port for an observed URL when none is explicit."""
    return 443 if scheme == "https" else 80


def _iso(value: datetime.datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _endpoint_assessment(db, scan_id: int) -> dict:
    """Map normalized endpoint URL -> executed/validated/failed test summary.

    Only AssessmentTest rows whose status is executed/validated/failed count;
    ``planned``/``skipped`` tests never make an endpoint "assessed".  The
    summary is deterministic (persisted statuses only) so the UI can answer
    "was this endpoint actually assessed" without guessing.
    """
    from database.models import AssessmentTest

    tests = (
        db.query(AssessmentTest)
        .filter(AssessmentTest.scan_id == scan_id,
                AssessmentTest.status.in_(_ASSESSED_TEST_STATUSES))
        .all()
    )
    agg: dict[str, dict] = {}
    for test in tests:
        url = normalize_endpoint(test.endpoint or "")
        if not url:
            continue
        entry = agg.setdefault(url, {"statuses": {}, "tests": 0})
        entry["statuses"][test.status] = entry["statuses"].get(test.status, 0) + 1
        entry["tests"] += 1
    return agg


def endpoint_inventory(db, scan_id: int, *, limit: int = 500) -> list[dict]:
    """Deduplicated observed endpoint URLs (query-stripped) with provenance."""
    from database.models import Observation

    entries: dict[tuple, dict] = {}

    def _at(row) -> datetime.datetime | None:
        return row.observed_at or row.created_at

    rows = db.query(Observation).filter(Observation.scan_id == scan_id).all()
    for row in rows:
        if (row.kind or "") in _NON_INVENTORY_KINDS:
            continue
        subject = (row.subject or "").strip()
        if not subject.startswith("http"):
            continue
        url = subject.split("#", 1)[0]
        parts = urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https") or not parts.hostname:
            continue
        endpoint = normalize_endpoint(url)
        from app.discovery.endpoints import endpoint_key

        key = endpoint_key(endpoint)
        entry = entries.get(key)
        if entry is None:
            entry = {
                "url": endpoint,
                "scheme": scheme,
                "host": (parts.hostname or "").lower(),
                "port": parts.port or _default_port(scheme),  # explicit or scheme default
                "method": None,  # never inferred from an observed URL
                "sources": [],
                "kinds": [],
                "observation_ids": [],
                "first_seen": None,
                "last_seen": None,
                "parameters": [],
            }
            entries[key] = entry
        source = (row.source or row.tool_name or "unknown")
        kind = row.kind or "observation"
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if kind not in entry["kinds"]:
            entry["kinds"].append(kind)
        if isinstance(row.id, int) and row.id not in entry["observation_ids"]:
            entry["observation_ids"].append(row.id)
        entry["observation_ids"] = entry["observation_ids"][-12:]
        at = _at(row)
        if at is not None:
            if entry["first_seen"] is None or at < entry["first_seen"]:
                entry["first_seen"] = at
            if entry["last_seen"] is None or at > entry["last_seen"]:
                entry["last_seen"] = at
        from app.discovery.endpoints import query_parameters

        for name in query_parameters(url):
            if name not in entry["parameters"]:
                entry["parameters"].append(name)

    out = sorted(entries.values(), key=lambda e: (str(e["first_seen"] or ""), e["url"]))
    assessed = _endpoint_assessment(db, scan_id)
    for item in out:
        item["parameter_count"] = len(item["parameters"])
        item["first_seen"] = _iso(item["first_seen"])
        item["last_seen"] = _iso(item["last_seen"])
        detail = assessed.get(item["url"])
        item["assessed"] = detail is not None
        item["assessment_statuses"] = sorted(detail["statuses"]) if detail else []
        item["assessment_tests"] = detail["tests"] if detail else 0
        del item["parameters"]
    return out[:limit]


def _discovery_assets(db, scan_id: int, kinds: tuple[str, ...]) -> list[dict]:
    from database.models import Observation

    rows = (
        db.query(Observation)
        .filter(Observation.scan_id == scan_id, Observation.kind.in_(kinds))
        .order_by(Observation.id.asc())
        .all()
    )
    return [
        {
            "id": row.id,
            "url": row.subject,
            "kind": row.kind,
            "data": row.data_json or {},
            "source": row.source or row.tool_name,
            "observed_at": _iso(row.observed_at or row.created_at),
        }
        for row in rows
    ]


def api_documents(db, scan_id: int) -> list[dict]:
    """Observed machine-readable API documents (``api_document`` rows)."""
    return _discovery_assets(db, scan_id, ("api_document",))


def script_assets(db, scan_id: int) -> list[dict]:
    """Observed static script assets (``script_asset`` rows)."""
    return _discovery_assets(db, scan_id, ("script_asset",))


def surface_coverage(db, scan_id: int) -> dict:
    """Endpoint/parameter coverage: observed vs actually assessed.

    An endpoint is *assessed* when persisted AssessmentTest rows (executed,
    validated or failed) produced observations at that endpoint.  Parameters on
    assessed endpoints follow the same gate.  Counts are honest: no observed
    surface => nothing assessed.
    """
    from database.models import AssessmentTest, Observation

    tests = (
        db.query(AssessmentTest)
        .filter(AssessmentTest.scan_id == scan_id,
                AssessmentTest.status.in_(_ASSESSED_TEST_STATUSES))
        .all()
    )
    assessed_endpoints: set[str] = set()
    for test in tests:
        endpoint = normalize_endpoint(test.endpoint or "")
        if endpoint:
            assessed_endpoints.add(endpoint)
        for obs_id in test.observation_ids or []:
            row = db.query(Observation).filter(Observation.id == obs_id).first()
            if row is None:
                continue
            subject = (row.subject or "").strip()
            if subject.startswith("http"):
                assessed_endpoints.add(normalize_endpoint(subject))

    endpoints = endpoint_inventory(db, scan_id)
    parameters = parameter_inventory(db, scan_id)
    assessed_param_names: set[str] = set()
    for item in parameters:
        if normalize_endpoint(item["endpoint"]) in assessed_endpoints:
            assessed_param_names.add(item["parameter"])

    return {
        "endpoints_total": len(endpoints),
        "endpoints_assessed": len(assessed_endpoints),
        "parameters_total": len(parameters),
        "parameters_assessed": len(assessed_param_names),
        "note": ("Endpoints assessed = endpoints where executed/validated/failed "
                 "assessment tests produced observations."),
    }


def surface_snapshot(db, scan) -> dict:
    """One scan's full surface summary (context + inventory + coverage)."""
    from app.discovery.context import scan_context

    endpoints = endpoint_inventory(db, scan.id)
    parameters = parameter_inventory(db, scan.id)
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "context": scan_context(db, scan),
        "endpoints": endpoints,
        "endpoint_count": len(endpoints),
        "parameters": parameters,
        "parameter_count": len(parameters),
        "api_documents": api_documents(db, scan.id),
        "script_assets": script_assets(db, scan.id),
        "coverage": surface_coverage(db, scan.id),
        "note": ("Surface facts are derived from persisted observations; values "
                 "are never surfaced and methods are never inferred."),
    }


__all__ = [
    "endpoint_inventory", "parameter_inventory", "api_documents",
    "script_assets", "surface_coverage", "surface_snapshot",
]