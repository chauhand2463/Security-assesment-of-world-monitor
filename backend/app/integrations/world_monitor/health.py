"""Real World Monitor health/connectivity check (Phase 8, hardened in 10.9).

A health check issues a real, scope-guarded GET against the configured base
URL and records whatever the deployment actually returned: HTTP status,
response timing, detected server/application metadata and TLS information when
HTTPS is used.  The result is *reachability*, never a security verdict -- HTTP
200 only means the request returned successfully.

Scope is enforced before the request and again on every redirect hop (the
reused ``SafeHttpClient`` does both).  An out-of-scope destination is recorded
as a blocked step, not probed.

Phase 10.9: transient network errors (URLError/Timeout/OSError surfaced as
``status == 0``) are retried a bounded number of times with exponential
backoff.  Nothing here ever retries a scoped-away destination or an HTTP-level
verdict; a response that came back (any HTTP status) is the observed truth.
"""
from __future__ import annotations

import datetime
import time
import urllib.parse

from app.http.client import HttpLimits, OutOfScopeError, SafeHttpClient
from app.http.fingerprints import technology_hints
from app.integrations.world_monitor.models import HealthResult

_TIMEOUT_SECONDS = 8.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_SECONDS = 0.25


def _transient_error(resp) -> bool:
    """True only for network-level failures worth retrying.

    A response with ``status == 0`` means the transport itself failed
    (URLError / Timeout / OSError); any real HTTP status (including 5xx) is
    an observed server answer and is never the subject of a retry.
    """
    return resp is not None and resp.status == 0 and bool(resp.error)


def _valid_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url or "")
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def check_health(url: str, scope_guard, client: SafeHttpClient | None = None,
                 max_retries: int = _DEFAULT_MAX_RETRIES,
                 backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS) -> HealthResult:
    """Probe ``url`` with a real request, retrying transient network errors.

    Returns a HealthResult (never raises for network conditions; raises only
    for internal misuse).  ``max_retries`` bounds the number of *additional*
    attempts beyond the first; transient failures between attempts sleep
    ``backoff_seconds * 2 ** attempt``.
    """
    url = (url or "").strip().rstrip("/") or ""
    now = datetime.datetime.utcnow().isoformat()

    if not _valid_url(url):
        return HealthResult(url=url, reachable=False, http_status=0, error="invalid or unsupported URL",
                            checked_at=now)

    if not scope_guard(url):
        return HealthResult(url=url, reachable=False, http_status=0,
                            error="blocked: destination outside authorized scope", checked_at=now)

    if client is None:
        client = SafeHttpClient(
            scope_guard,
            HttpLimits(active_testing=False, request_timeout=_TIMEOUT_SECONDS),
            capture_tls=url.startswith("https://"),
        )

    resp = None
    attempts = 0
    try:
        while True:
            attempts += 1
            try:
                candidate = client.get(url)
            except OutOfScopeError as exc:
                return HealthResult(url=url, reachable=False, http_status=0,
                                    error=f"blocked: {exc}", checked_at=now)
            if not _transient_error(candidate) or attempts > max_retries:
                resp = candidate
                break
            time.sleep(backoff_seconds * (2 ** (attempts - 1)))
    except KeyboardInterrupt:  # pragma: no cover - do not silently swallow Ctrl+C
        raise

    if resp.error and resp.status == 0:
        return HealthResult(url=url, reachable=False, http_status=0, elapsed_ms=resp.elapsed_ms,
                            error=str(resp.error), checked_at=now)

    headers = {str(k): (", ".join(str(x) for x in v) if isinstance(v, list) else str(v))
               for k, v in (resp.headers or {}).items()}
    server = headers.get("Server") or headers.get("server")
    metadata = technology_hints(headers)
    metadata_payload = {
        "content_type": resp.content_type,
        "technology_hints": metadata,
        "redirect_chain": list(resp.redirect_chain or []),
    }

    return HealthResult(
        url=url,
        reachable=resp.status > 0,
        http_status=resp.status,
        elapsed_ms=resp.elapsed_ms,
        server=server,
        version_hint=metadata[0]["value"] if metadata and metadata[0]["kind"] == "server" else None,
        detected_metadata=metadata_payload,
        tls=resp.tls,
        error=None,
        checked_at=now,
    )


__all__ = ["check_health"]