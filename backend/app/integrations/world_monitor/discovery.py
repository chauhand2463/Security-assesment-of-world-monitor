"""World Monitor API discovery (Phase 8) -- first layer only.

Ordered discovery is driven strictly by explicit configuration, then by what
the live deployment actually responds with:

  1. base URL          -- the configured health-check root,
  2. API base URL      -- the configured API base (when set),
  3. OpenAPI URL       -- the configured OpenAPI document (when set),
  4. common metadata   -- explicitly *not* guessed; recorded as unsupported,
  5. frontend refs     -- only when a frontend source is supplied (none yet).

The integration never brute-forces paths and never crawls arbitrary URLs, so it
cannot become a scan primitive outside the operator's explicit configuration.
An out-of-scope destination is recorded as ``blocked`` and not fetched.
"""
from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from typing import Callable, NamedTuple

from app.http.client import HttpLimits, OutOfScopeError, SafeHttpClient
from app.integrations.world_monitor.health import check_health
from app.integrations.world_monitor.models import (
    APIEndpoint,
    DiscoveryResult,
    DiscoveryStep,
    OPENAPI_AVAILABLE,
    OPENAPI_UNAVAILABLE,
    OPENAPI_UNCONFIGURED,
    RPC_UNSUPPORTED,
    SOURCE_API_BASE,
    SOURCE_BASE_URL,
    SOURCE_FRONTEND,
    SOURCE_OPENAPI,
    STEP_BLOCKED,
    STEP_REACHABLE,
    STEP_UNAVAILABLE,
    STEP_UNSUPPORTED,
    WORLD_MONITOR_STATUS_DISCOVERED,
    WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED,
    WORLD_MONITOR_STATUS_REACHABLE,
    WORLD_MONITOR_STATUS_UNAVAILABLE,
)

_TIMEOUT_SECONDS = 8.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_SECONDS = 0.25


class TargetConfig(NamedTuple):
    """The World Monitor URLs the operator explicitly configured."""

    base_url: str
    api_base_url: str | None = None
    openapi_url: str | None = None


def _parse_openapi_document(document: dict, source: str = SOURCE_OPENAPI) -> list[APIEndpoint]:
    """Extract API endpoints from an OpenAPI 3.x ``paths`` map (no guessing)."""
    paths = document.get("paths") or {}
    if not isinstance(paths, dict) or not paths:
        return []
    endpoints: list[APIEndpoint] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            op = op if isinstance(op, dict) else {}
            security = op.get("security")
            auth_hint = None
            if not security and document.get("security"):
                security = document["security"]
            if isinstance(security, list) and security:
                schemes = [k for entry in security if isinstance(entry, dict) for k in entry.keys()]
                if schemes:
                    auth_hint = "required" if op.get("security") else "possible"
            endpoints.append(APIEndpoint(
                method=method.upper(),
                path=path,
                operation_id=op.get("operationId"),
                tags=list(op.get("tags") or []),
                source=source,
                authentication_hint=auth_hint,
            ))
    return endpoints


_HTTP_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
})


def discover(target: TargetConfig, scope_guard: Callable[[str], bool],
             client: SafeHttpClient | None = None, parse_openapi=None,
             max_retries: int = _DEFAULT_MAX_RETRIES,
             backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS) -> DiscoveryResult:
    """Run the ordered World Monitor discovery sequence.

    ``parse_openapi`` defaults to :func:`_parse_openapi_document`; it is
    injectable so tests can stub document parsing without touching HTTP.

    Phase 10.9: individual probe steps retry transient network failures
    (``status == 0``) with exponential backoff; scoped-away destinations and
    real HTTP responses are never retried.
    """
    started = datetime.datetime.utcnow().isoformat()
    base_url = (target.base_url or "").strip().rstrip("/")
    result = DiscoveryResult(base_url=base_url, started_at=started)

    if not base_url:
        result.target_status = WORLD_MONITOR_STATUS_UNAVAILABLE
        result.error = "not_configured: no World Monitor base URL"
        result.finished_at = started
        return result

    if client is None:
        client = SafeHttpClient(scope_guard,
                                HttpLimits(active_testing=False, request_timeout=_TIMEOUT_SECONDS),
                                capture_tls=base_url.startswith("https://"))

    # --- 1. base URL -------------------------------------------------------
    step_order = 0
    health = check_health(base_url, scope_guard, client,
                          max_retries=max_retries, backoff_seconds=backoff_seconds)
    result.health = health
    if health.error and "outside authorized scope" in (health.error or ""):
        result.steps.append(DiscoveryStep(step_order, SOURCE_BASE_URL, base_url,
                                          STEP_BLOCKED, health.error))
        result.target_status = WORLD_MONITOR_STATUS_UNAVAILABLE
        result.error = health.error
        result.finished_at = datetime.datetime.utcnow().isoformat()
        return result
    if health.reachable:
        result.steps.append(DiscoveryStep(step_order, SOURCE_BASE_URL, base_url,
                                          STEP_REACHABLE,
                                          f"HTTP {health.http_status} in {health.elapsed_ms:.1f} ms"))
    else:
        reason = health.error or f"HTTP status {health.http_status}"
        result.steps.append(DiscoveryStep(step_order, SOURCE_BASE_URL, base_url,
                                          STEP_UNAVAILABLE, f"base URL unreachable: {reason}"))
        result.target_status = WORLD_MONITOR_STATUS_UNAVAILABLE
        result.error = reason
        result.finished_at = datetime.datetime.utcnow().isoformat()
        return result
    result.target_status = WORLD_MONITOR_STATUS_REACHABLE

    # --- 2. API base URL (only when explicitly configured) ------------------
    if target.api_base_url:
        step_order += 1
        api_base = target.api_base_url.strip().rstrip("/")
        status, detail = _probe_url(client, scope_guard, api_base,
                                    max_retries=max_retries, backoff_seconds=backoff_seconds)
        result.steps.append(DiscoveryStep(step_order, SOURCE_API_BASE, api_base,
                                          status, detail))
        if status == STEP_REACHABLE:
            result.target_status = WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED

    # --- 3. OpenAPI document (only when explicitly configured) --------------
    if target.openapi_url:
        step_order += 1
        openapi_url = target.openapi_url.strip().rstrip("/")
        doc, status, detail = _fetch_document(client, scope_guard, openapi_url,
                                              max_retries=max_retries, backoff_seconds=backoff_seconds)
        if status == STEP_REACHABLE and doc:
            parser = parse_openapi or _parse_openapi_document
            endpoints = parser(doc, source=SOURCE_OPENAPI)
            result.endpoints.extend(endpoints)
            result.openapi_status = OPENAPI_AVAILABLE
            info = doc.get("info") or {}
            version = info.get("version")
            if version:
                result.discovered_version = str(version)
            detail = (detail or "") + (
                f"; parsed {len(endpoints)} operation(s) from {len(doc.get('paths') or {})} path(s)"
                if (doc.get("paths") or {}) else "; document contains no paths map")
            result.steps.append(DiscoveryStep(step_order, SOURCE_OPENAPI, openapi_url,
                                              STEP_REACHABLE, detail))
            result.target_status = (WORLD_MONITOR_STATUS_DISCOVERED if endpoints
                                    else WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED)
        else:
            result.openapi_status = OPENAPI_UNAVAILABLE
            result.steps.append(DiscoveryStep(step_order, SOURCE_OPENAPI, openapi_url,
                                              status, detail))
    else:
        result.openapi_status = OPENAPI_UNCONFIGURED

    # --- 4/5. common metadata + frontend references: explicitly NOT guessed --
    if not target.openapi_url:
        result.steps.append(DiscoveryStep(
            step_order + 1, "metadata",
            "(none configured)",
            STEP_UNSUPPORTED,
            "no metadata source was configured; endpoint paths are never guessed",
        ))
    result.steps.append(DiscoveryStep(
        step_order + 2, SOURCE_FRONTEND,
        "(none configured)",
        STEP_UNSUPPORTED,
        "no World Monitor frontend URL was configured for reference discovery",
    ))
    result.steps.append(DiscoveryStep(
        step_order + 3, "rpc",
        "(none configured)",
        STEP_UNSUPPORTED,
        f"rpc_status={RPC_UNSUPPORTED}: no RPC metadata source is configured or observed",
    ))

    if result.target_status == WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED and result.endpoints:
        result.target_status = WORLD_MONITOR_STATUS_DISCOVERED

    result.finished_at = datetime.datetime.utcnow().isoformat()
    return result


def _probe_url(client: SafeHttpClient, scope_guard: Callable[[str], bool],
               url: str, max_retries: int = _DEFAULT_MAX_RETRIES,
               backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS) -> tuple[str, str]:
    if not scope_guard(url):
        return STEP_BLOCKED, "API base URL outside authorized scope (not fetched)"
    resp, attempts, _blocked = _get_with_retries(client, url,
                                                 max_retries=max_retries, backoff_seconds=backoff_seconds)
    if _blocked:
        return STEP_BLOCKED, _blocked
    if resp.status > 0:
        detail = f"HTTP {resp.status} in {resp.elapsed_ms:.1f} ms"
        if attempts > 1:
            detail += f" (after {attempts} attempt(s))"
        return STEP_REACHABLE, detail
    return STEP_UNAVAILABLE, f"HTTP request failed: {resp.error or 'no response'}"


def _fetch_document(client: SafeHttpClient, scope_guard: Callable[[str], bool],
                    url: str, max_retries: int = _DEFAULT_MAX_RETRIES,
                    backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS) -> tuple[dict | None, str, str]:
    """Fetch and parse a JSON document. Returns (document, status, detail)."""
    if not scope_guard(url):
        return None, STEP_BLOCKED, "OpenAPI URL outside authorized scope (not fetched)"
    resp, attempts, _blocked = _get_with_retries(client, url,
                                                 max_retries=max_retries, backoff_seconds=backoff_seconds)
    if _blocked:
        return None, STEP_BLOCKED, _blocked
    if resp.status <= 0:
        return None, STEP_UNAVAILABLE, f"HTTP request failed: {resp.error or 'no response'}"
    if resp.status >= 400:
        return None, STEP_UNAVAILABLE, f"HTTP {resp.status}: document not served"
    try:
        doc = json.loads(resp.body or "{}")
    except (ValueError, TypeError) as exc:
        return None, STEP_UNAVAILABLE, f"body not valid JSON ({exc})"
    detail = f"HTTP {resp.status}; valid OpenAPI document"
    if attempts > 1:
        detail += f" (after {attempts} attempt(s))"
    if isinstance(doc, dict) and "paths" in doc:
        return doc, STEP_REACHABLE, detail
    return doc, STEP_REACHABLE, (f"HTTP {resp.status}; JSON served without a paths map"
                                 if isinstance(doc, dict) else "HTTP {resp.status}; non-object JSON")


class _BlockedResponse:
    """Sentinel for a redirect that left authorized scope (never retried)."""

    status = 0
    error = ""
    elapsed_ms = 0.0


def _get_with_retries(client: SafeHttpClient, url: str, *,
                      max_retries: int = _DEFAULT_MAX_RETRIES,
                      backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS) -> tuple[object, int, str]:
    """GET ``url`` retrying transient network failures with bounded backoff.

    Returns ``(response, attempts, blocked_reason)``.  A blocked redirect
    (OutOfScopeError) or a real HTTP response (any status) ends the loop
    immediately.
    """
    import time

    from app.integrations.world_monitor.health import _transient_error

    attempts = 0
    while True:
        attempts += 1
        try:
            resp = client.get(url)
        except OutOfScopeError as exc:
            return _BlockedResponse(), attempts, f"redirect left authorized scope: {exc}"
        if not _transient_error(resp) or attempts > max_retries:
            return resp, attempts, ""
        time.sleep(backoff_seconds * (2 ** (attempts - 1)))


__all__ = [
    "TargetConfig", "discover", "_parse_openapi_document", "_HTTP_METHODS",
]