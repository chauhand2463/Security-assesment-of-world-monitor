"""Dimension coverage -- what the scan actually observed (Phase 10.11, G9).

Task coverage (``scan.coverage``) only measures *how many planned tasks ran to
success*.  Dimension coverage answers a different, honest question: across the
real persisted evidence of a scan, how many distinct hosts / ports / URLs were
actually observed, and which tools produced each dimension fact.

Everything here is derived strictly from real rows:

  * ``observations`` for the scan (host/port/URL subjects + structured data),
  * ``assets`` first surfaced by the scan (asset graph rows).

No dimension is guessed: a host is only counted once an Observation references
it; a port only once an Observation's structured data carries a ``port``; a URL
only once an Observation's subject is a real http(s) URL.  ``by_tool`` groups
the observed facts by the tool that captured them, so a report can say exactly
what each tool saw instead of implying it observed everything.
"""
from __future__ import annotations

from app.http.fingerprints import host_of

DIMENSION_HOST = "hosts"
DIMENSION_PORT = "ports"
DIMENSION_URL = "urls"


def _port_from_data(data: dict) -> int | None:
    if not isinstance(data, dict):
        return None
    raw = data.get("port")
    if raw is None:
        return None
    try:
        return int(str(raw).split("/", 1)[0])
    except (TypeError, ValueError):
        return None


def dimension_coverage(db, scan_id: int, target: str = "") -> dict:
    """Compute observed dimension coverage for a scan from real rows.

    Returns ``{"hosts": {...}, "ports": {...}, "urls": {...}, "by_tool": {...}}``
    where each dimension has ``observed`` (count), ``distinct`` (values) and
    ``tools`` (which tools captured facts in that dimension).
    """
    from database.models import Observation

    hosts: set[str] = set()
    ports: set[int] = set()
    urls: set[str] = set()
    by_tool: dict[str, dict] = {}

    rows = (
        db.query(Observation)
        .filter(Observation.scan_id == scan_id)
        .order_by(Observation.id.asc())
        .all()
    )

    def _record(tool: str, dimension: str, value):
        entry = by_tool.setdefault(tool or "unknown", {"observations": 0, "hosts": [], "ports": [], "urls": []})
        entry["observations"] += 1
        if dimension == DIMENSION_HOST and value and value not in entry["hosts"]:
            entry["hosts"].append(value)
        elif dimension == DIMENSION_PORT and value is not None and value not in entry["ports"]:
            entry["ports"].append(value)
        elif dimension == DIMENSION_URL and value and value not in entry["urls"]:
            entry["urls"].append(value)

    for obs in rows:
        data = obs.data_json or {}
        tool = obs.tool_name or "unknown"
        subject = (obs.subject or "").strip()

        # host dimension -- any observation tied to a host/asset
        host = obs.asset or None
        if not host:
            host = host_of(subject) or None
        if not host and subject and "://" not in subject:
            host = subject
        if host:
            host_lower = str(host).lower()
            hosts.add(host_lower)
            _record(tool, DIMENSION_HOST, host_lower)

        # port dimension -- structured data carries "port"
        port = _port_from_data(data)
        if port is not None:
            ports.add(port)
            _record(tool, DIMENSION_PORT, port)

        # URL dimension -- subject is a real http(s) URL
        if subject.lower().startswith(("http://", "https://")):
            urls.add(subject)
            _record(tool, DIMENSION_URL, subject)

    observed_target = None
    if target and (host_of(target) or target.lower()) in hosts:
        observed_target = host_of(target) or target.lower()

    return {
        DIMENSION_HOST: {
            "observed": len(hosts),
            "distinct": sorted(hosts),
            "tools": sorted({t for t, e in by_tool.items() if e["hosts"]}),
        },
        DIMENSION_PORT: {
            "observed": len(ports),
            "distinct": sorted(ports),
            "tools": sorted({t for t, e in by_tool.items() if e["ports"]}),
        },
        DIMENSION_URL: {
            "observed": len(urls),
            "distinct": sorted(urls),
            "tools": sorted({t for t, e in by_tool.items() if e["urls"]}),
        },
        "scan_target_observed": observed_target,
        "by_tool": {
            tool: {
                "observations": e["observations"],
                "hosts": len(e["hosts"]),
                "ports": len(e["ports"]),
                "urls": len(e["urls"]),
            }
            for tool, e in sorted(by_tool.items())
        },
    }


__all__ = ["dimension_coverage", "DIMENSION_HOST", "DIMENSION_PORT", "DIMENSION_URL"]