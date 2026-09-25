"""Phase 12 parameter inventory (real persisted observations only).

A parameter appears in the inventory if and only if it was *observed*: either as
an explicit ``parameter_candidate`` (from Phase 11 document discovery) or as a
query-string name on a persisted HTTP(S) observation subject.  Parameter values
are never surfaced -- only the name, its existence shape, and provenance.  The
redaction invariants hold: the inventory API echoes names, never values.
"""
from __future__ import annotations

import datetime
from urllib.parse import parse_qs, urlsplit

from app.discovery.endpoints import endpoint_key, without_query
from app.observations.normalize import normalize_endpoint as _normalize_endpoint

# Kinds that carry an observed-but-refused out-of-scope subject; their subject
# URLs must never enter the inventory (they were refused by the scope guard).
_NON_INVENTORY_KINDS = {"endpoint_out_of_scope", "wm_not_configured"}

# Default for a parameter whose name appears in a sensitive-key dictionary:
# still real surface facts, but flagged so dashboards can treat them carefully.
_SENSITIVE_NAME_HINTS = {"token", "secret", "password", "passwd", "pwd", "key",
                         "apikey", "api_key", "auth", "jwt", "session", "cookie"}


def _parameter_value_shape(values: list[str]) -> str:
    """``present`` if any observed value was non-empty, else ``empty``."""
    return "present" if any(v != "" for v in values) else "empty"


def query_parameter_items(url: str) -> list[tuple[str, str]]:
    """(name, value_shape) pairs observed on a URL's query string."""
    query = urlsplit(url).query
    if not query:
        return []
    parsed = parse_qs(query, keep_blank_values=True)
    items: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, values in parsed.items():
        name = str(name).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        items.append((name, _parameter_value_shape(values)))
    return items


def _parameter_rows(db, scan_id: int):
    """Yield rows that may contribute parameters (skipping refused subjects)."""
    from database.models import Observation

    for row in db.query(Observation).filter(Observation.scan_id == scan_id).all():
        if (row.kind or "") in _NON_INVENTORY_KINDS:
            continue
        subject = (row.subject or "").strip()
        if subject.startswith("http"):
            yield row, subject


def parameter_inventory(db, scan_id: int, *, limit: int = 1000) -> list[dict]:
    """Observed parameter names per endpoint, deduplicated and provenance-rich.

    ``value_shape`` is ``present``/``empty`` (existence only -- never a value).
    ``first_seen``/``last_seen`` are the earliest/latest observation timestamps.
    """
    params: dict[tuple[str, str], dict] = {}

    def _at(row) -> datetime.datetime | None:
        return row.observed_at or row.created_at

    for row, subject in _parameter_rows(db, scan_id):
        endpoint = _normalize_endpoint(without_query(subject))
        if not endpoint:
            continue
        declared = (row.data_json or {}).get("parameter")
        candidates: list[tuple[str, str]] = []
        if isinstance(declared, str) and declared.strip():
            candidates.append((declared.strip(), "present"))
        candidates.extend(query_parameter_items(subject))

        for name, shape in candidates:
            key = (endpoint_key(endpoint), name)
            entry = params.get(key)
            if entry is None:
                entry = {
                    "endpoint": endpoint,
                    "parameter": name,
                    "value_shape": shape,
                    "value_sensitive": name.lower() in _SENSITIVE_NAME_HINTS,
                    "sources": [],
                    "kinds": [],
                    "observation_ids": [],
                    "first_seen": None,
                    "last_seen": None,
                }
                params[key] = entry
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

    out = sorted(
        params.values(),
        key=lambda e: (
            str(e["endpoint"]),
            str(e["parameter"]),
        ),
    )
    from app.discovery.inventory import _endpoint_assessment

    assessed = _endpoint_assessment(db, scan_id)
    for item in out:
        detail = assessed.get(item["endpoint"])
        item["assessed"] = detail is not None
        item["assessment_statuses"] = sorted(detail["statuses"]) if detail else []
    return out[:limit]


__all__ = ["parameter_inventory", "query_parameter_items"]