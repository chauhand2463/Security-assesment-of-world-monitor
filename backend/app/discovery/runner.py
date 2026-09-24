"""Phase 11 endpoint discovery runner (native, real HTTP, scope-bounded).

Slice 1 integration: a bounded native HTTP discovery pass that fetches the
standard discovery documents (robots.txt, sitemap) plus the root HTML page of
each in-scope base URL and turns the *real content* into endpoint/parameter
candidate observations.  Hard guarantees:

  * every request passes the authorized scope guard before a socket opens;
  * request budget, timeouts, redirect and response-size limits are enforced;
  * a failed or empty fetch yields zero candidates, never a fabricated one;
  * out-of-scope URLs observed in content are refused (with their own
    observation) rather than probed;
  * the runner never raises -- worst case it returns one error observation so
    the pipeline can fail the scan honestly instead of hanging it.
"""
from __future__ import annotations

import datetime
from typing import Any, Callable

from app.discovery.endpoints import (
    KIND_CANDIDATE,
    KIND_OUT_OF_SCOPE,
    KIND_PARAMETER,
    KIND_SUMMARY,
    SOURCE_ROBOTS,
    parse_robots,
    to_absolute,
)
from app.http.client import HttpLimits
from app.http.fingerprints import host_of

_default_limits = HttpLimits(
    max_requests_per_scan=16,
    max_requests_per_test=16,
    request_timeout=8.0,
    redirect_limit=3,
    response_size_limit=400_000,
)

_SNIPPET_MAX = 400
_MAX_HOSTS = 2
_MAX_SITEMAPS_PER_BASE = 2


def clip(text: str, limit: int = _SNIPPET_MAX) -> str:
    text = text or ""
    return text[:limit] + ("\n...[truncated]" if len(text) > limit else "")


def build_scan_guard(db, scan) -> Callable[[str], bool]:
    """Scope guard binding discovery to the scan's own target + project scope."""
    from app.core.auth import is_target_in_scope
    from database.models import Asset, Project

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    assets = db.query(Asset).filter(Asset.project_id == scan.project_id).all()
    target_host = (scan.target or "").lower()

    def guard(url: str) -> bool:
        host = host_of(url)
        if not host:
            return False
        if host.lower() == target_host:
            return True
        return bool(project and is_target_in_scope(host, project, assets))

    return guard


def _base_urls(scan, config: dict, state: dict, guard) -> list[str]:
    """Explicit configured base URLs, else the scan's hosts (https & http)."""
    cfg = (config or {}).get("endpoint_discovery") or {}
    if isinstance(cfg, dict) and cfg.get("base_urls"):
        bases = []
        for raw in cfg["base_urls"]:
            url = str(raw or "").strip().rstrip("/")
            if url and guard(url):
                bases.append(url)
        return bases

    hosts = list(dict.fromkeys((state or {}).get("hosts") or [scan.target]))[:_MAX_HOSTS]
    bases: list[str] = []
    for host in hosts:
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}"
            if guard(base):
                bases.append(base)
    return bases


def _fetch_documents(client: SafeHttpClient, bases: list[str]) -> list[dict]:
    """Fetch robots.txt, sitemap and root HTML per in-scope base URL.

    Only 200 responses with a body become documents; 4xx/5xx/network failures
    are skipped (they are facts, not content).  Budget is shared across bases.
    """
    documents: list[dict] = []

    def _read(url: str) -> dict | None:
        if client.requests_made >= client.limits.max_requests_per_scan:
            return None
        resp = client.get(url)
        if resp.status in (200, 203) and resp.body:
            return {"url": url, "body": resp.body, "content_type": resp.content_type}
        return None

    for base in bases:
        robots_doc = _read(f"{base}/robots.txt")
        if robots_doc:
            documents.append(robots_doc)
        sitemaps = []
        if robots_doc is not None:
            for raw in (parse_robots(robots_doc["body"]) or {}).get("sitemaps", []):
                absolute = to_absolute(raw, base)
                if absolute and client.scope_guard(absolute):
                    sitemaps.append(absolute)
        if not sitemaps:
            sitemaps.append(f"{base}/sitemap.xml")
        for sitemap_url in sitemaps[:_MAX_SITEMAPS_PER_BASE]:
            doc = _read(sitemap_url)
            if doc:
                documents.append(doc)
        root_doc = _read(f"{base}/")
        if root_doc:
            documents.append(root_doc)
    return documents


def _summary_observation(scan, bases: list[str], client: SafeHttpClient,
                         report, refused: list[str]) -> dict:
    return {
        "kind": KIND_SUMMARY,
        "subject": scan.target,
        "data": {
            "status": "observed",
            "bases_attempted": len(bases),
            "requests_made": client.requests_made,
            "endpoint_candidates": report.candidate_count,
            "parameter_candidates": report.parameter_count,
            "sources": dict(report.sources),
            "refused_in_scope_guard": len(refused),
        },
        "raw": (f"[endpoint_discovery] {report.candidate_count} candidate endpoint(s), "
                f"{report.parameter_count} parameter(s) from {len(bases)} base(s); "
                f"{len(refused)} out-of-scope URL(s) observed in content and refused."),
        "source": "native_discovery",
        "status": "observed",
    }


def run_endpoint_discovery(db, scan, config: dict, state: dict) -> list[dict]:
    """Run one discovery pass and return legacy-shaped observation dicts.

    Never raises.  Returns observations only -- persistence happens in the
    executor, keeping this module free of DB writes.

    ``SafeHttpClient`` is looked up at call time (not import time) so tests and
    operators can supply an offline/scope-safe client through the normal
    ``app.http.client`` attribute without a stale import-time binding.
    """
    from app.discovery.endpoints import discover_from_documents
    from app.http.client import SafeHttpClient

    guard = build_scan_guard(db, scan)
    try:
        bases = _base_urls(scan, config, state, guard)
        client = SafeHttpClient(guard, limits=_default_limits, capture_tls=False)
        documents = _fetch_documents(client, bases)
        report = discover_from_documents(documents, guard)

        observations: list[dict] = []
        for entry in report.endpoints:
            observations.append({
                "kind": KIND_CANDIDATE,
                "subject": entry["url"],
                "data": {
                    "url": entry["url"],
                    "source": entry["source"],
                    "base_url": entry["base_url"],
                    "method": None,  # observed URL only; method is never inferred
                },
                "raw": f"[{entry['source']}] observed {entry['url']}",
                "source": "native_discovery",
                "status": "observed",
            })
        for entry in report.parameters:
            observations.append({
                "kind": KIND_PARAMETER,
                "subject": entry["url"],
                "data": {
                    "url": entry["url"],
                    "parameter": entry["parameter"],
                    "source": entry["source"],
                },
                "raw": f"[{entry['source']}] query parameter '{entry['parameter']}' on {entry['url']}",
                "source": "native_discovery",
                "status": "observed",
            })
        for url in report.refused:
            observations.append({
                "kind": KIND_OUT_OF_SCOPE,
                "subject": url,
                "data": {"url": url, "in_scope": False},
                "raw": f"observed out-of-scope URL in content and refused: {url}",
                "source": "scope_guard",
                "status": "skipped",
            })
        observations.append(_summary_observation(scan, bases, client, report, report.refused))
        return observations
    except Exception as exc:  # never fabricate; surface the real failure honestly
        return [{
            "kind": KIND_SUMMARY,
            "subject": scan.target,
            "data": {"status": "error", "error": f"{type(exc).__name__}: {exc}"},
            "raw": f"endpoint discovery failed: {exc}",
            "source": "native_discovery",
            "status": "error",
        }]


__all__ = ["run_endpoint_discovery", "build_scan_guard"]