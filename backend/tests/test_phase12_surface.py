"""Phase 12 slice 1 -- surface intelligence tests (real evidence only).

Covers the inventory pipeline end to end:
  * OpenAPI/JS discovery parsing (JSON-only, honest for YAML),
  * parameter/endpoint inventory aggregation from persisted observations,
  * surface coverage (observed vs assessed) and the deterministic surface plan,
  * live fixture-server integration producing script_asset / api_* observations,
  * the additive typed-event ledger entries, and the Phase 12 API endpoints.
"""
import http.server
import json
import threading
import uuid

import pytest

from app.discovery.openapi import parse_openapi
from app.discovery.js import script_assets_from_documents
from app.discovery.parameters import parameter_inventory
from app.discovery.context import scan_context
from app.discovery.inventory import (
    endpoint_inventory,
    surface_coverage,
    surface_snapshot,
)
from app.assess.surface_planner import plan_surface
from app.orchestration import events, executions
from database.models import (
    AssessmentTest, Observation, Project, Scan, ScanEvent, User,
)


def _scope_guard(url: str) -> bool:
    return url.startswith("https://in.example") or url.startswith("http://127.0.0.1")


def _make_scan(session, target="127.0.0.1", config=None):
    owner = User(id=f"p12-{uuid.uuid4().hex[:8]}",
                 email=f"p12-{uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p12", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="",
                scan_config=config)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


# ---------------------------------------------------------------------------
# OpenAPI parser (JSON-only, honest)
# ---------------------------------------------------------------------------

def test_parse_openapi_json_document():
    body = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "demo", "version": "1"},
        "servers": [{"url": "https://in.example"}],
        "paths": {
            "/items": {
                "parameters": [{"name": "sort", "in": "query", "required": False}],
                "get": {"parameters": [{"name": "order", "in": "query"}]},
                "post": {"parameters": [{"name": "body", "in": "body"}]},
            }
        },
    })
    doc = parse_openapi(body, "https://in.example/openapi.json", _scope_guard)
    assert doc["parsed"] is True
    assert doc["base"] == "https://in.example"
    methods = {(e["method"], e["url"]) for e in doc["endpoints"]}
    assert ("GET", "https://in.example/items") in methods
    assert ("POST", "https://in.example/items") in methods
    params = {(p["parameter"], p["location"]) for p in doc["parameters"]}
    assert ("sort", "query") in params and ("order", "query") in params
    assert all(p["source"] == "openapi" for p in doc["parameters"])


def test_parse_openapi_yaml_is_honest_unsupported():
    body = "openapi: 3.0.0\ninfo:\n  title: demo\npaths: {}\n"
    doc = parse_openapi(body, "https://in.example/openapi.yaml", _scope_guard)
    assert doc["parsed"] is False
    assert "not a JSON document" in doc["reason"]
    assert doc["endpoints"] == [] and doc["parameters"] == []


def test_parse_openapi_no_paths_section_is_not_parsed():
    doc = parse_openapi('{"hello": "world"}', "https://in.example/utils.json", _scope_guard)
    assert doc["parsed"] is False
    assert "no 'paths'" in doc["reason"]


def test_parse_openapi_falls_back_to_in_scope_document_origin():
    body = json.dumps({
        "servers": [{"url": "https://evil.example"}],
        "paths": {"/x": {"get": {}}},
    })
    doc = parse_openapi(body, "https://in.example/openapi.json", _scope_guard)
    # the declared server is out of scope; the observed, in-scope document origin
    # becomes the base, so no endpoint leaves the authorized scope.
    assert doc["parsed"] is True
    assert doc["base"] == "https://in.example"
    assert all(e["url"].startswith("https://in.example") for e in doc["endpoints"])


# ---------------------------------------------------------------------------
# JS script assets
# ---------------------------------------------------------------------------

def test_script_assets_from_documents_dedupe_and_scope():
    docs = [
        {"url": "https://in.example/", "body":
            '<script src="/app.js"></script><script src="/app.js"></script>'
            '<script src="https://cdn.evil.example/x.js"></script>'},
        {"url": "https://in.example/page", "body": '<script src="./lib.js"></script>'},
    ]
    assets = script_assets_from_documents(docs, _scope_guard)
    urls = {a["url"] for a in assets}
    assert urls == {
        "https://in.example/app.js",
        "https://in.example/lib.js",  # ./lib.js resolves against the dir of /page => /
    }
    assert all(a["kind"] == "script_asset" for a in assets)


# ---------------------------------------------------------------------------
# inventory aggregation (persisted observations only)
# ---------------------------------------------------------------------------

def _insert_scan_observations(session, scan, rows):
    ids = []
    for r in rows:
        row = Observation(scan_id=scan.id, tool_name="t", kind=r["kind"],
                          subject=r["subject"], data_json=r.get("data", {}),
                          source=r.get("source", "probe"),
                          status=r.get("status", "observed"),
                          raw_output=r.get("raw", ""))
        session.add(row)
        session.flush()
        ids.append(row.id)
    session.commit()
    return ids


def test_endpoint_and_parameter_inventory_from_observations(session):
    scan = _make_scan(session)
    _insert_scan_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://in.example/a?p=1&p=2",
         "source": "html"},
        {"kind": "endpoint_candidate", "subject": "https://in.example/a?x=3",
         "source": "sitemap"},
        {"kind": "endpoint_out_of_scope", "subject": "https://evil.example/z",
         "source": "scope_guard", "status": "skipped"},
        {"kind": "parameter_candidate", "subject": "https://in.example/a?p=1",
         "data": {"parameter": "p"}, "source": "html"},
        {"kind": "endpoint_candidate", "subject": "https://in.example/b"},
    ])

    eps = endpoint_inventory(session, scan.id)
    urls = {e["url"] for e in eps}
    assert urls == {"https://in.example/a", "https://in.example/b"}
    a = next(e for e in eps if e["url"] == "https://in.example/a")
    assert "html" in a["sources"] and "sitemap" in a["sources"]
    assert a["observation_ids"] and a["first_seen"] and a["last_seen"]
    # the out-of-scope URL never enters the inventory
    assert not any(e["host"] == "evil.example" for e in eps)

    params = parameter_inventory(session, scan.id)
    assert {p["parameter"] for p in params} == {"p", "x"}
    assert all("value_shape" in p for p in params)
    assert all("value" not in p for p in params)  # values are never surfaced


def test_surface_coverage_counts_only_assessed_endpoints(session):
    scan = _make_scan(session)
    _insert_scan_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "http://in.example/a"},
        {"kind": "endpoint_candidate", "subject": "http://in.example/b?q=1"},
        {"kind": "parameter_candidate", "subject": "http://in.example/b?q=1",
         "data": {"parameter": "q"}},
    ])

    cov = surface_coverage(session, scan.id)
    assert cov["endpoints_total"] == 2 and cov["endpoints_assessed"] == 0
    assert cov["parameters_total"] == 1 and cov["parameters_assessed"] == 0

    # now a real assessed test row for endpoint /b exists
    session.add(AssessmentTest(
        scan_id=scan.id, test_id="params.xss", name="XSS", category="xss",
        status="validated", reason="evidence", endpoint="http://in.example/b?q=1",
        observation_ids=[], finding_ids=[],
    ))
    session.commit()

    cov = surface_coverage(session, scan.id)
    assert cov["endpoints_assessed"] == 1
    assert cov["parameters_assessed"] == 1


def test_scan_context_groups_hosts_ports_and_sources(session):
    scan = _make_scan(session)
    _insert_scan_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://in.example:8443/a", "source": "html"},
        {"kind": "endpoint_candidate", "subject": "https://in.example/b", "source": "sitemap"},
        {"kind": "parameter_candidate", "subject": "https://other.example/v?k=1", "source": "html"},
    ])
    ctx = scan_context(session, scan)
    hosts = {h["host"]: h for h in ctx["hosts"]}
    assert set(hosts) == {"in.example", "other.example"}
    assert hosts["in.example"]["schemes"] == ["https"]
    assert 8443 in hosts["in.example"]["ports"]
    assert 443 in hosts["in.example"]["ports"]  # default for https scheme
    assert hosts["other.example"]["ports"] == [443]
    assert ctx["observation_count"] == 3
    assert "html" in ctx["sources"] and "sitemap" in ctx["sources"]


def test_surface_snapshot_is_full_and_values_never_surface(session):
    scan = _make_scan(session)
    _insert_scan_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://in.example/a?t=1"},
        {"kind": "api_document", "subject": "https://in.example/openapi.json",
         "data": {"status": "parsed"}},
        {"kind": "script_asset", "subject": "https://in.example/app.js"},
    ])
    snap = surface_snapshot(session, scan)
    # every observed URL is surfaced, including the API doc and script asset.
    assert snap["endpoint_count"] == 3
    assert any(e["url"] == "https://in.example/app.js" for e in snap["endpoints"])
    assert len(snap["api_documents"]) == 1
    assert len(snap["script_assets"]) == 1
    assert snap["context"]["host_count"] >= 1
    assert "coverage" in snap


# ---------------------------------------------------------------------------
# deterministic surface plan
# ---------------------------------------------------------------------------

def test_surface_plan_is_deterministic_planned_or_skipped_with_reason(session):
    scan = _make_scan(session)
    _insert_scan_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://in.example/search?q=1"},
        {"kind": "parameter_candidate", "subject": "https://in.example/search?q=1",
         "data": {"parameter": "q"}},
    ])
    plan = plan_surface(session, scan)
    d = plan.to_dict()
    assert d["tests_total"] > 0
    # every registered test is either planned against observed surface or
    # skipped with a concrete, deterministic reason.
    assert all(t["status"] in ("planned", "skipped") for t in d["tasks"])
    assert all(t["reason"] for t in d["tasks"])
    xss = next((t for t in d["tasks"] if t["test_id"] == "injection.xss.reflected"), None)
    if xss is not None:
        assert xss["parameters"] == ["q"]
        assert "https://in.example/search" in xss["endpoints"]


def test_surface_plan_skips_everything_with_empty_surface(session):
    scan = _make_scan(session)
    d = plan_surface(session, scan).to_dict()
    assert d["tests_total"] > 0
    assert d["tests_planned"] == 0
    assert d["tests_skipped"] == d["tests_total"]
    assert all("no observed" in t["reason"] or "not surface-scoped" in t["reason"]
               for t in d["tasks"])


# ---------------------------------------------------------------------------
# live fixture server integration (script + OpenAPI observed)
# ---------------------------------------------------------------------------

class _Phase12Handler(http.server.BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, str, str]] = {}

    def log_message(self, *args):  # silence test noise
        pass

    def do_GET(self):  # noqa: N802
        status, ctype, body = self.routes.get(self.path, (404, "text/plain", "nope"))
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def openapi_serving_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Phase12Handler)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    openapi = {
        "openapi": "3.0.0",
        "info": {"title": "fixture", "version": "1"},
        "servers": [{"url": base}],
        "paths": {"/api/users": {"get": {"parameters": [
            {"name": "page", "in": "query"}]}}},
    }
    _Phase12Handler.routes = {
        "/": (200, "text/html", '<html><head></head><body>'
                                '<script src="/app.min.js"></script></body></html>'),
        "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /admin\n"),
        "/openapi.json": (200, "application/json", json.dumps(openapi)),
    }
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield base
    server.shutdown()
    thread.join(timeout=5)


def test_discovery_persists_script_assets_and_api_facts(session, openapi_serving_server):
    session.rollback()  # discard any uncommitted state left by earlier tests
    base = openapi_serving_server
    scan = _make_scan(session, target="127.0.0.1",
                      config={"tools": {"endpoint_discovery": True},
                              "endpoint_discovery": {"base_urls": [base]}})
    result = executions.execute_tool(session, scan, "endpoint_discovery",
                                     scan.scan_config, None, {})
    assert result["status"] == "success"
    session.commit()

    rows = session.query(Observation).filter(
        Observation.scan_id == scan.id).all()
    kinds = {r.kind for r in rows}
    assert "script_asset" in kinds
    assert "api_document" in kinds
    assert "api_endpoint_candidate" in kinds
    assert "api_parameter_candidate" in kinds

    doc = next(r for r in rows if r.kind == "api_document")
    assert doc.data_json["status"] == "parsed"
    assert doc.data_json["declared_endpoints"] == 1

    api_ep = next(r for r in rows if r.kind == "api_endpoint_candidate")
    assert api_ep.data_json["method"] == "GET"
    assert api_ep.subject.endswith("/api/users")

    api_param = next(r for r in rows if r.kind == "api_parameter_candidate")
    assert api_param.data_json["parameter"] == "page"

    eps = endpoint_inventory(session, scan.id)
    assert any(e["url"].endswith("/app.min.js") for e in eps)
    assert any(e["url"].endswith("/api/users") for e in eps)


def test_discovery_emits_typed_endpoint_parameter_events(session, openapi_serving_server):
    session.rollback()
    base = openapi_serving_server
    scan = _make_scan(session, target="127.0.0.1",
                      config={"tools": {"endpoint_discovery": True},
                              "endpoint_discovery": {"base_urls": [base]}})
    executions.execute_tool(session, scan, "endpoint_discovery",
                            scan.scan_config, None, {})
    session.commit()

    ev = session.query(ScanEvent).filter(ScanEvent.scan_id == scan.id).all()
    ledgers = {e.event_type for e in ev}
    assert events.EVENT_ENDPOINT in ledgers
    assert events.EVENT_PARAMETER in ledgers
    assert events.EVENT_OBSERVATION in ledgers


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

def _api_scan(client, auth_headers, target):
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    resp = client.post("/scans", json={"target": target}, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["scan_id"]


def test_api_surface_inventory_and_plan(client, auth_headers, session):
    session.rollback()
    target = "ph12-api.example.com"
    scan_id = _api_scan(client, auth_headers, target)
    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    obs_ids = _insert_scan_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://ph12-api.example.com/x?q=1",
         "source": "html"},
        {"kind": "parameter_candidate", "subject": "https://ph12-api.example.com/x?q=1",
         "data": {"parameter": "q"}, "source": "html"},
    ])
    events.emit_endpoint_discovered(session, scan.id, obs_ids[0],
                                    "https://ph12-api.example.com/x", "endpoint_candidate", "html")
    session.commit()

    p = client.get(f"/scans/{scan_id}/surface", headers=auth_headers)
    assert p.status_code == 200, p.text
    body = p.json()
    assert body["endpoint_count"] == 1
    assert body["coverage"]["endpoints_total"] == 1

    ep = client.get(f"/scans/{scan_id}/surface/endpoints", headers=auth_headers).json()
    assert ep["endpoints"][0]["url"] == "https://ph12-api.example.com/x"

    params = client.get(f"/scans/{scan_id}/surface/parameters", headers=auth_headers).json()
    assert params["parameters"][0]["parameter"] == "q"
    assert "value" not in params["parameters"][0]

    plan = client.get(f"/scans/{scan_id}/assessment-plan", headers=auth_headers)
    assert plan.status_code == 200, plan.text
    assert plan.json()["tests_total"] > 0

    tl = client.get(f"/scans/{scan_id}/timeline", headers=auth_headers).json()
    assert any(i["type"] == events.EVENT_ENDPOINT for i in tl["items"])


def test_api_surface_diff_between_two_scans(client, auth_headers, session):
    session.rollback()
    target = "ph12-diff.example.com"
    first = _api_scan(client, auth_headers, target)
    scan1 = session.query(Scan).filter(Scan.id == first).first()
    _insert_scan_observations(session, scan1, [
        {"kind": "endpoint_candidate", "subject": "https://ph12-diff.example.com/a"},
        {"kind": "endpoint_candidate", "subject": "https://ph12-diff.example.com/b?k=1"},
    ])

    second = _api_scan(client, auth_headers, target)
    scan2 = session.query(Scan).filter(Scan.id == second).first()
    _insert_scan_observations(session, scan2, [
        {"kind": "endpoint_candidate", "subject": "https://ph12-diff.example.com/a"},
        {"kind": "endpoint_candidate", "subject": "https://ph12-diff.example.com/c"},
    ])

    body = client.get(f"/scans/{second}/diff", headers=auth_headers).json()
    assert body["compare_to"] == first
    assert body["endpoints_added"] == ["https://ph12-diff.example.com/c"]
    assert body["endpoints_removed"] == ["https://ph12-diff.example.com/b"]
    assert "parameters_added" in body

    cov = client.get(f"/scans/{first}/coverage", headers=auth_headers).json()
    assert cov["surface"]["endpoints_total"] == 2
    assert cov["surface"]["endpoints_assessed"] == 0


def test_api_surface_respects_ownership(client, auth_headers, other_auth_headers, session):
    session.rollback()
    target = "ph12-owned.example.com"
    scan_id = _api_scan(client, auth_headers, target)
    resp = client.get(f"/scans/{scan_id}/surface", headers=other_auth_headers)
    assert resp.status_code == 404  # platform convention: non-owner -> not found