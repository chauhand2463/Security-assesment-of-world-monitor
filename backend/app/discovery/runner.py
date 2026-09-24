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
    OPENAPI_CANDIDATE_PATHS,
    SOURCE_ROBOTS,
    parse_robots,
    to_absolute,
)
from app.http.client import HttpLimits
from app.http.fingerprints import host_of

_default_limits = HttpLimits(
    max_requests_per_scan=28,
    max_requests_per_test=28,
    request_timeout=8.0,
    redirect_limit=3,
    response_size_limit=400_000,
)

_SNIPPET_MAX = 400
_MAX_HOSTS = 2
_MAX_SITEMAPS_PER_BASE = 2
_MAX_OPENAPI_PER_BASE = len(OPENAPI_CANDIDATE_PATHS)


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
                         report, refused: list[str], extra: dict | None = None) -> dict:
    extra = extra or {}
    return {
        "kind": KIND_SUMMARY,
        "subject": scan.target,
        "data": {
            "status": "observed",
            "bases_attempted": len(bases),
            "requests_made": client.requests_made,
            "endpoint_candidates": report.candidate_count,
            "parameter_candidates": report.parameter_count,
            "script_assets": extra.get("script_assets", 0),
            "api_documents": extra.get("api_documents", 0),
            "api_endpoint_candidates": extra.get("api_endpoint_candidates", 0),
            "api_parameter_candidates": extra.get("api_parameter_candidates", 0),
            "sources": dict(report.sources),
            "refused_in_scope_guard": len(refused),
        },
        "raw": (f"[endpoint_discovery] {report.candidate_count} candidate endpoint(s), "
                f"{report.parameter_count} parameter(s) from {len(bases)} base(s); "
                f"{extra.get('script_assets', 0)} script asset(s), "
                f"{extra.get('api_endpoint_candidates', 0)} API endpoint(s); "
                f"{len(refused)} out-of-scope URL(s) observed in content and refused."),
        "source": "native_discovery",
        "status": "observed",
    }


def _fetch_openapi_candidates(client: SafeHttpClient, bases: list[str],
                              guard) -> list[dict]:
    """Probe well-known OpenAPI document locations per base (GET, bounded).

    Probing stops for a base at the first document that *parses*; a 2xx page
    that is not a parseable OpenAPI document is still recorded as an observed
    ``api_document`` with an honest parse status.  Nothing is fetched outside
    the scope guard or the request budget.
    """
    from app.discovery.openapi import parse_openapi

    observations: list[dict] = []
    for base in bases:
        for candidate in OPENAPI_CANDIDATE_PATHS:
            if client.requests_made >= client.limits.max_requests_per_scan:
                break
            url = f"{base.rstrip('/')}{candidate}"
            if not guard(url):
                continue
            resp = client.get(url)
            if resp.status not in (200, 203) or not resp.body:
                continue
            parsed = parse_openapi(resp.body, url, guard)
            observations.append({
                "kind": "api_document",
                "subject": url,
                "data": {
                    "url": url,
                    "status": "parsed" if parsed["parsed"] else "unsupported",
                    "reason": parsed["reason"],
                    "declared_endpoints": len(parsed["endpoints"]),
                    "declared_parameters": len(parsed["parameters"]),
                },
                "raw": (f"[openapi] {url}: {parsed['reason']}; "
                        f"{len(parsed['endpoints'])} endpoint(s), "
                        f"{len(parsed['parameters'])} parameter(s) declared."),
                "source": "native_discovery",
                "status": "observed",
            })
            for endpoint in parsed["endpoints"]:
                observations.append({
                    "kind": "api_endpoint_candidate",
                    "subject": endpoint["url"],
                    "data": {
                        "url": endpoint["url"],
                        "method": endpoint["method"],
                        "source": "openapi",
                        "source_document": endpoint["source_url"],
                    },
                    "raw": (f"[openapi] declares {endpoint['method']} {endpoint['url']}"),
                    "source": "native_discovery",
                    "status": "observed",
                })
            for parameter in parsed["parameters"]:
                observations.append({
                    "kind": "api_parameter_candidate",
                    "subject": parameter["url"],
                    "data": {
                        "url": parameter["url"],
                        "parameter": parameter["parameter"],
                        "location": parameter["location"],
                        "required": parameter["required"],
                        "source": "openapi",
                        "source_document": parameter["source_url"],
                    },
                    "raw": (f"[openapi] declares parameter '{parameter['parameter']}' "
                            f"({parameter['location']}) on {parameter['url']}"),
                    "source": "native_discovery",
                    "status": "observed",
                })
            if parsed["parsed"]:
                break
    return observations


def run_endpoint_discovery(db, scan, config: dict, state: dict) -> list[dict]:
    """Run one discovery pass and return legacy-shaped observation dicts.

    Never raises.  Returns observations only -- persistence happens in the
    executor, keeping this module free of DB writes.

    ``SafeHttpClient`` is looked up at call time (not import time) so tests and
    operators can supply an offline/scope-safe client through the normal
    ``app.http.client`` attribute without a stale import-time binding.
    """
    from app.discovery.endpoints import discover_from_documents
    from app.discovery.js import script_assets_from_documents
    from app.http.client import SafeHttpClient

    guard = build_scan_guard(db, scan)
    try:
        bases = _base_urls(scan, config, state, guard)
        client = SafeHttpClient(guard, limits=_default_limits, capture_tls=False)
        documents = _fetch_documents(client, bases)
        report = discover_from_documents(documents, guard)
        script_assets = script_assets_from_documents(documents, guard)
        api_observations = _fetch_openapi_candidates(client, bases, guard)

        extras = {
            "script_assets": len(script_assets),
            "api_documents": sum(1 for o in api_observations if o["kind"] == "api_document"),
            "api_endpoint_candidates": sum(1 for o in api_observations if o["kind"] == "api_endpoint_candidate"),
            "api_parameter_candidates": sum(1 for o in api_observations if o["kind"] == "api_parameter_candidate"),
        }

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
        for asset in script_assets:
            observations.append({
                "kind": asset["kind"],
                "subject": asset["url"],
                "data": {
                    "url": asset["url"],
                    "source": asset["source"],
                    "base_url": asset["base_url"],
                },
                "raw": f"[{asset['source']}] static script asset {asset['url']}",
                "source": "native_discovery",
                "status": "observed",
            })
        observations.extend(api_observations)
        observations.append(_summary_observation(scan, bases, client, report,
                                                 report.refused, extras))
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