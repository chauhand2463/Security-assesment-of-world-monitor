"""World Monitor provider -- the narrow integration boundary (Phase 8).

The rest of the application talks to World Monitor only through this class.
It exposes the three minimum operations required by the phase:

  * ``check_health``      -- one real, scope-guarded connectivity probe,
  * ``discover``          -- the ordered discovery sequence,
  * ``get_api_inventory`` -- deterministic OpenAPI → endpoint normalization.

Every request is real HTTP via the existing scope-safe client and never
fabricates data.  Out-of-scope destinations are recorded as blocked.
"""
from __future__ import annotations

from typing import Callable

from app.http.client import HttpLimits, SafeHttpClient
from app.integrations.world_monitor import discovery as discovery_mod
from app.integrations.world_monitor import health as health_mod
from app.integrations.world_monitor.models import APIEndpoint, DiscoveryResult, HealthResult

_DEFAULT_TIMEOUT_SECONDS = 8.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_SECONDS = 0.25


class WorldMonitorProvider:
    """Thin, deterministic facade over real World Monitor probes."""

    def __init__(self, scope_guard: Callable[[str], bool],
                 client: SafeHttpClient | None = None,
                 timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
                 max_retries: int = _DEFAULT_MAX_RETRIES,
                 backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS) -> None:
        if client is None:
            client = SafeHttpClient(
                scope_guard,
                HttpLimits(active_testing=False, request_timeout=timeout_seconds),
            )
        self.scope_guard = scope_guard
        self.client = client
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds

    def check_health(self, base_url: str) -> HealthResult:
        """One real health/connectivity probe (reachability, never a verdict)."""
        return health_mod.check_health(
            base_url, self.scope_guard, self.client,
            max_retries=self.max_retries, backoff_seconds=self.backoff_seconds,
        )

    def discover(self, target: discovery_mod.TargetConfig) -> DiscoveryResult:
        """Run the ordered discovery sequence for ``target``."""
        client = SafeHttpClient(
            self.scope_guard,
            HttpLimits(active_testing=False, request_timeout=_DEFAULT_TIMEOUT_SECONDS),
            capture_tls=(target.base_url or "").startswith("https://"),
        )
        return discovery_mod.discover(
            target, self.scope_guard, client,
            max_retries=self.max_retries, backoff_seconds=self.backoff_seconds,
        )

    def get_api_inventory(self, openapi_document: dict) -> list[APIEndpoint]:
        """Deterministically normalize an OpenAPI document into endpoints.

        Pure function: parses ``paths`` into endpoint rows without any network
        access or guessing of operation ids/parameters.
        """
        return discovery_mod._parse_openapi_document(openapi_document or {}, source="openapi")


__all__ = ["WorldMonitorProvider"]