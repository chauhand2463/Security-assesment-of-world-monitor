"""Phase 10.9 -- World Monitor reliability.

Covers the three hardening commitments from the Phase 10 gap register:

  * bounded retry with exponential backoff on *transient network errors* only
    (never on scoped-away destinations or real HTTP verdicts),
  * staleness surfacing in the World Monitor target API,
  * an explicit, visible scan -> target bridge (no inference).

The retry tests drive a real localhost fixture that drops connection attempts
(fast, deterministic), a counting test double for exact attempt accounting, and
the real provider against the fixture.
"""
from __future__ import annotations

import datetime
import http.server
import json
import socket
import threading
import urllib.error
import urllib.request
from urllib.parse import urlparse

import pytest

from app.http.client import HttpLimits, SafeHttpClient
from app.http.responses import HTTPResponse
from app.integrations.world_monitor import models as wm_models
from app.integrations.world_monitor.discovery import TargetConfig, discover
from app.integrations.world_monitor.health import _transient_error, check_health
from app.integrations.world_monitor.provider import WorldMonitorProvider

OPENAPI_DOC = {
    "openapi": "3.0.3",
    "info": {"title": "World Monitor Fixture", "version": "1.2.3"},
    "paths": {
        "/health": {
            "get": {
                "operationId": "getHealth",
                "tags": ["health"],
            },
        },
    },
}


class _RoutingHandler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def _respond(self):
        r = urlparse(self.path)
        route = self.routes.get(r.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, headers, body = route
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        else:
            body = (body or "").encode("utf-8")
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._respond()

    def log_message(self, *args):  # pragma: no cover - quiet the test server
        pass


def _make_server(routes: dict):
    handler = type("FixtureHandler", (_RoutingHandler,), {"routes": routes})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return f"http://{host}:{port}", server


@pytest.fixture()
def wm_base():
    routes = {
        "/": (200, {"Server": "WM-Server/1.2"}, "<html>World Monitor</html>"),
        "/api": (200, {"Content-Type": "application/json"}, {"status": "ok"}),
        "/openapi.json": (200, {"Content-Type": "application/json"}, OPENAPI_DOC),
    }
    base, server = _make_server(routes)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def cleanup_wm_targets(client, auth_headers):
    """Delete any World Monitor targets created during the test.

    The test database is shared across files and pytest ordering is lexical
    (``test_phase10_*`` sorts before ``test_phase8_*``), so target rows left
    behind would break phase8's pristine-list flow test.  Teardown-only: the
    tests themselves still assert the exact rows they created.
    """
    yield
    res = client.get("/world-monitor/targets", headers=auth_headers)
    if res.status_code >= 400:
        return
    for t in (res.json() or []):
        client.delete(f"/world-monitor/targets/{t['id']}", headers=auth_headers)


@pytest.fixture()
def transient_server():
    """A server that resets the connection once, then serves normally."""
    dropped = {"count": 0}

    class Flaky(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if dropped["count"] == 0:
                dropped["count"] += 1
                self.connection.close()
                return
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # pragma: no cover
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Flaky)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        yield base, dropped
    finally:
        server.shutdown()
        server.server_close()


def _guard(base: str):
    def guard(url: str) -> bool:
        host = (urlparse(url).netloc or "").lower()
        allowed = (urlparse(base).netloc or "").lower()
        return host == allowed
    return guard


def _closed_port_url():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


class _CountingClient:
    """Test double for ``SafeHttpClient`` that counts calls."""

    def __init__(self, responses: list[HTTPResponse]):
        self._responses = list(responses)
        self.calls = 0

    def get(self, url: str, **kw) -> HTTPResponse:
        self.calls += 1
        if not self._responses:
            return HTTPResponse(status=0, url=url, error="no responses left")
        return self._responses.pop(0)


def _transient_response(url: str) -> HTTPResponse:
    return HTTPResponse(status=0, url=url, error="timed out")


def _ok_response(url: str, status: int = 200) -> HTTPResponse:
    return HTTPResponse(status=status, url=url)


# ---------------------------------------------------------------------------
# transient-error classification
# ---------------------------------------------------------------------------
def test_transient_error_classifier():
    assert _transient_error(HTTPResponse(status=0, url="u", error="timed out")) is True
    assert _transient_error(HTTPResponse(status=0, url="u", error="refused")) is True
    assert _transient_error(HTTPResponse(status=200, url="u")) is False
    assert _transient_error(HTTPResponse(status=503, url="u", error="boom")) is False
    assert _transient_error(None) is False


# ---------------------------------------------------------------------------
# bounded retry with backoff (exact attempt counting via the test double)
# ---------------------------------------------------------------------------
def test_check_health_retries_transient_until_success():
    url = "http://wm.example"
    probe = _CountingClient([
        _transient_response(url),
        _transient_response(url),
        _ok_response(url),
    ])
    result = check_health(url, lambda _u: True, probe, max_retries=3, backoff_seconds=0)
    assert probe.calls == 3
    assert result.reachable is True
    assert result.http_status == 200
    assert result.error is None


def test_check_health_gives_up_at_bound_with_transient_persists():
    url = "http://wm.example"
    probe = _CountingClient([
        _transient_response(url),
        _transient_response(url),
        _transient_response(url),
    ])
    result = check_health(url, lambda _u: True, probe, max_retries=2, backoff_seconds=0)
    assert probe.calls == 3  # 1 initial + exactly 2 bounded retries
    assert result.reachable is False
    assert "timed out" in (result.error or "")


def test_check_health_never_retries_a_real_http_verdict():
    url = "http://wm.example"
    probe = _CountingClient([_ok_response(url, status=500)])
    result = check_health(url, lambda _u: True, probe, max_retries=3, backoff_seconds=0)
    assert probe.calls == 1
    assert result.reachable is True
    assert result.http_status == 500


def test_check_health_never_retries_scoped_away_destination():
    url = "http://not-allowed.example"
    probe = _CountingClient([])
    result = check_health(url, lambda _u: False, probe, max_retries=3, backoff_seconds=0)
    assert probe.calls == 0
    assert result.reachable is False
    assert "outside authorized scope" in (result.error or "")


def test_discovery_retries_base_url_through_connection_reset(transient_server):
    base, dropped = transient_server
    result = discover(TargetConfig(base_url=base), lambda _u: True,
                      max_retries=3, backoff_seconds=0)
    assert dropped["count"] == 1          # the transient drop really happened
    assert result.health is not None
    assert result.health.reachable is True
    assert result.target_status == "reachable"
    assert result.error is None


def test_health_retries_against_real_flaky_server(transient_server):
    base, dropped = transient_server
    result = check_health(base, lambda _u: True, max_retries=3, backoff_seconds=0)
    assert dropped["count"] == 1
    assert result.reachable is True
    assert result.http_status == 200


def test_discovery_openapi_probe_retries_transiently(transient_server):
    base, dropped = transient_server
    flaky_okapi = _CountingClient([
        _transient_response(f"{base}/openapi.json"),
        _ok_response(f"{base}/openapi.json"),
    ])
    client = SafeHttpClient(lambda _u: True, HttpLimits(active_testing=False))
    original_get = client.get

    def get(url: str, **kw):
        if url.endswith("/openapi.json"):
            return flaky_okapi.get(url, **kw)
        return original_get(url, **kw)

    client.get = get  # type: ignore[method-assign]
    result = discover(TargetConfig(base_url=base, openapi_url=f"{base}/openapi.json"),
                      lambda _u: True, client=client)
    assert result.health is not None and result.health.reachable is True
    assert result.target_status in ("reachable", "partially_discovered")
    assert flaky_okapi.calls == 2


# ---------------------------------------------------------------------------
# staleness surfacing in the target API
# ---------------------------------------------------------------------------
def test_api_target_payload_surfaces_staleness(client, auth_headers, wm_base, cleanup_wm_targets):
    created = client.post("/world-monitor/targets", json={"base_url": wm_base},
                          headers=auth_headers).json()
    body = client.get(f"/world-monitor/targets/{created['id']}", headers=auth_headers).json()
    staleness = body["staleness"]
    assert stameless_state(staleness) == "never_checked"
    assert staleness["seconds_since_last_check"] is None


def stameless_state(staleness: dict) -> str:
    return staleness["state"]


def test_api_check_surfaces_fresh_state(client, auth_headers, wm_base, cleanup_wm_targets):
    created = client.post("/world-monitor/targets", json={"base_url": wm_base},
                          headers=auth_headers).json()
    checked = client.post(f"/world-monitor/targets/{created['id']}/check",
                          headers=auth_headers).json()
    staleness = checked["staleness"]
    assert staleness["state"] == "fresh"
    assert isinstance(staleness["seconds_since_last_check"], int)


def test_api_staleness_detects_aged_probe(client, auth_headers, wm_base, session, cleanup_wm_targets):
    from database.models import WorldMonitorTarget

    created = client.post("/world-monitor/targets", json={"base_url": wm_base},
                          headers=auth_headers).json()
    client.post(f"/world-monitor/targets/{created['id']}/check", headers=auth_headers)
    row = session.query(WorldMonitorTarget).filter(WorldMonitorTarget.id == created["id"]).one()
    row.last_checked_at = datetime.datetime.utcnow() - datetime.timedelta(days=30)
    session.commit()

    body = client.get(f"/world-monitor/targets/{created['id']}", headers=auth_headers).json()
    staleness = body["staleness"]
    assert staleness["state"] == "stale"
    assert staleness["seconds_since_last_check"] >= 30 * 24 * 3600 - 60


# ---------------------------------------------------------------------------
# explicit scan -> target bridge (never inferred)
# ---------------------------------------------------------------------------
def test_bridge_is_explicit_only(client, auth_headers, wm_base, cleanup_wm_targets):
    # Explicit bridge: the scan that opts into this target is listed.
    created = client.post("/world-monitor/targets", json={"base_url": wm_base},
                          headers=auth_headers).json()
    tid = created["id"]
    target_host = wm_base.split("//")[1]
    explicit = client.post("/scans", headers=auth_headers, json={
        "target": target_host,
        "assessment_type": "world_monitor",
        "authorization_acknowledged": True,
        "world_monitor": {"target_id": tid},
    })
    assert explicit.status_code in (200, 403), explicit.text
    body = client.get(f"/world-monitor/targets/{tid}", headers=auth_headers).json()
    if explicit.status_code == 200:
        assert body["bridged_scans"] == [explicit.json()["scan_id"]]
    else:
        assert body["bridged_scans"] == []

    # A custom-target scan of the same host is NOT added to the bridge list.
    # Both assertions share one live target id so a fresh target -- whose numeric
    # id SQLite may reuse after teardown -- can never inherit an earlier scan.
    custom = client.post("/scans", headers=auth_headers, json={
        "target": target_host,
        "assessment_type": "custom_target",
        "authorization_acknowledged": True,
    })
    assert custom.status_code in (200, 403), custom.text
    body2 = client.get(f"/world-monitor/targets/{tid}", headers=auth_headers).json()
    expected = [explicit.json()["scan_id"]] if explicit.status_code == 200 else []
    assert body2["bridged_scans"] == expected
    if custom.status_code == 200:
        assert custom.json()["scan_id"] not in body2["bridged_scans"]