"""Phase 12 scan surface context (real persisted observations only).

Everything in here is derived from rows that were actually persisted -- never
guessed.  Hosts come from observation subjects, ports from the explicit port in
an observed URL (default-port schemes are recorded separately as observed
schemes), and counts from real rows.
"""
from __future__ import annotations

import datetime
from urllib.parse import urlsplit

from app.http.fingerprints import host_of, port_of


def _iso(value: datetime.datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def scan_context(db, scan) -> dict:
    """Aggregate one scan's observed network + surface facts into a dict."""
    from database.models import Asset, Observation

    project_id = scan.project_id
    hosts: dict[str, dict] = {}

    def _touch_host(url: str, when: datetime.datetime | None, kind: str) -> None:
        host = host_of(url)
        if not host:
            return
        entry = hosts.setdefault(host, {"schemes": [], "ports": [], "kinds": [],
                                        "first_seen": None, "last_seen": None})
        try:
            parts = urlsplit(url)
        except ValueError:
            return
        scheme = (parts.scheme or "").lower()
        if scheme and scheme not in entry["schemes"]:
            entry["schemes"].append(scheme)
        explicit = port_of(url, default=None)
        observed = explicit if explicit is not None else \
            (443 if scheme == "https" else 80 if scheme == "http" else None)
        if observed is not None and observed not in entry["ports"]:
            entry["ports"].append(observed)
        if kind not in entry["kinds"]:
            entry["kinds"].append(kind)
        if when is not None:
            if entry["first_seen"] is None or when < entry["first_seen"]:
                entry["first_seen"] = when
            if entry["last_seen"] is None or when > entry["last_seen"]:
                entry["last_seen"] = when

    rows = db.query(Observation).filter(Observation.scan_id == scan.id).all()
    kinds: dict[str, int] = {}
    sources: set[str] = set()
    first_seen: datetime.datetime | None = None
    last_seen: datetime.datetime | None = None
    http_subjects = 0

    for row in rows:
        kind = (row.kind or "observation") or "observation"
        kinds[kind] = kinds.get(kind, 0) + 1
        source = (row.source or row.tool_name or "unknown")
        if source:
            sources.add(source)
        when = row.observed_at or row.created_at
        if when is not None:
            if first_seen is None or when < first_seen:
                first_seen = when
            if last_seen is None or when > last_seen:
                last_seen = when
        subject = (row.subject or "").strip()
        if subject.startswith("http"):
            http_subjects += 1
            _touch_host(subject, when, kind)

    hosts_out: list[dict] = []
    for host in sorted(hosts):
        entry = hosts[host]
        hosts_out.append({
            "host": host,
            "schemes": sorted(entry["schemes"]),
            "ports": sorted(entry["ports"]),
            "kinds": sorted(set(entry["kinds"])),
            "first_seen": _iso(entry["first_seen"]),
            "last_seen": _iso(entry["last_seen"]),
        })

    asset_count = (
        db.query(Asset).filter(Asset.project_id == project_id).count()
        if project_id is not None else 0
    )

    return {
        "target": scan.target,
        "hosts": hosts_out,
        "host_count": len(hosts_out),
        "observation_count": len(rows),
        "http_subjects": http_subjects,
        "observation_kinds": dict(sorted(kinds.items())),
        "sources": sorted(sources),
        "asset_count": asset_count,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
    }


__all__ = ["scan_context"]