"""Phase 11 slice 1 — endpoint & parameter discovery tests.

Proves the "real evidence only" invariant end to end:
  * candidates are deduced from *real fetched content* (robots/sitemap/HTML),
  * a server returning no content produces zero candidates (no fabrication),
  * out-of-scope URLs observed in content are refused, never probed,
  * plans include/exclude the tool honestly, and a disabled tool skips without
    writing observations,
  * discovery observations carry explicit provenance (source/status).
"""
import http.server
import threading
import uuid

import pytest

from app.discovery.endpoints import (
    classify_document,
    discover_from_documents,
    links_from_html,
    parse_robots,
    parse_sitemap,
    query_parameters,
    to_absolute,
)
from app.orchestration import executions, stages
from database.models import Observation, Project, Scan, ToolExecution, ToolResult, User


def _make_scan(session, target="127.0.0.1", config=None):
    owner = User(id=f"p11-{uuid.uuid4().hex[:8]}",
                 email=f"p11-{uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p11", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="",
                scan_config=config)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


# ---------------------------------------------------------------------------
# pure parsing units
# ---------------------------------------------------------------------------

def test_links_from_html_collects_href_src_and_form_action():
    html = ('<a href="/a">A</a><form action="/search"><input name="q"></form>'
            '<img src="/static/logo.png"><script src="/app.js"></a>')
    links = links_from_html(html)
    assert "/a" in links and "/search" in links and "/static/logo.png" in links
    assert "/app.js" in links


def test_to_absolute_resolves_and_refuses_junk():
    assert to_absolute("/admin", "https://h.example") == "https://h.example/admin"
    assert to_absolute("items?page=1", "https://h.example/a/") == "https://h.example/a/items?page=1"
    assert to_absolute("//cdn.example/x", "https://h.example/") == "https://cdn.example/x"
    assert to_absolute("#top", "https://h.example/") is None
    assert to_absolute("javascript:alert(1)", "https://h.example/") is None
    assert to_absolute("mailto:a@b.c", "https://h.example/") is None
    assert to_absolute("https://user:secret@h.example/x", "https://h.example/") is None
    assert to_absolute("", "https://h.example/") is None
    assert to_absolute("ftp://h.example/x", "https://h.example/") is None


def test_fragment_stripped_and_query_preserved():
    url = to_absolute("https://h.example/path?b=2#frag", "https://h.example/")
    assert url == "https://h.example/path?b=2"


def test_query_parameters_extracted():
    assert query_parameters("https://h.example/api?page=2&sort=asc") == ["page", "sort"]
    assert query_parameters("https://h.example/x?a=1&a=2") == ["a"]
    assert query_parameters("https://h.example/x") == []


def test_parse_robots_honors_disallow_and_sitemap_lines():
    text = ("User-agent: *\nDisallow: /admin\nDisallow: /internal/?secret=1\n"
            "Sitemap: https://h.example/sitemap.xml\n# comment\nAllow: /public\n"
            "User-agent: BadBot\nDisallow: /")
    parsed = parse_robots(text)
    assert parsed["disallow"] == ["/admin", "/internal/?secret=1", "/"]
    assert parsed["sitemaps"] == ["https://h.example/sitemap.xml"]


def test_parse_sitemap_extracts_locs():
    xml = ('<?xml version="1.0"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           "<url><loc>https://h.example/</loc></url>"
           "<url><loc>https://h.example/contact</loc></url></urlset>")
    assert parse_sitemap(xml) == ["https://h.example/", "https://h.example/contact"]
    assert parse_sitemap("<urlset><url><loc>https://h.example/a</loc></url></urlset>") == \
        ["https://h.example/a"]
    assert parse_sitemap("not xml") == []


def test_classify_document():
    assert classify_document("https://h.example/robots.txt", "User-agent: *") == "robots"
    assert classify_document("https://h.example/sitemap.xml", "<?xml") == "sitemap"
    assert classify_document("https://h.example/sitemap-index.xml", "<urlset>", "text/xml") == "sitemap"
    assert classify_document("https://h.example/", "<!doctype html>", "text/html") == "html"
    assert classify_document("https://h.example/img", b"\x89PNG".decode("latin1"), "image/png") is None
    assert classify_document("https://h.example/", "") is None


def _scope_guard(ok_hosts=("h.example",)):
    def guard(url):
        return url.split("//", 1)[-1].split("/", 1)[0].split(":")[0].lower() in ok_hosts
    return guard


def test_discover_dedups_and_refuses_out_of_scope():
    documents = [
        {"url": "https://h.example/robots.txt", "content_type": "text/plain",
         "body": "User-agent: *\nDisallow: /admin\nDisallow: /api?page=3\n"},
        {"url": "https://h.example/sitemap.xml", "content_type": "application/xml",
         "body": "<urlset><url><loc>https://h.example/api?page=1</loc></url>"
                 "<url><loc>https://h.example/</loc></url></urlset>"},
        {"url": "https://h.example/", "content_type": "text/html",
         "body": '<a href="/api?page=2&sort=asc">x</a><a href="https://evil.example/steal">bad</a>'
                 '<a href="mailto:x@y.z">mail</a>'},
    ]
    report = discover_from_documents(documents, _scope_guard())

    urls = {e["url"] for e in report.endpoints}
    assert "https://h.example/admin" in urls
    assert "https://h.example/api" in urls            # deduped across robots/sitemap/html
    assert "https://h.example/" in urls
    assert "https://evil.example/steal" not in urls   # refused, not a candidate
    assert "mailto:x@y.z" not in urls

    params = {(p["parameter"], p["url"]) for p in report.parameters}
    assert ("page", "https://h.example/api") in params
    assert ("sort", "https://h.example/api") in params

    assert report.refused == ["https://evil.example/steal"]
    # Observed-THEN-de-duplicated: html contributes the /api link (1 derivation);
    # robots contributes /admin and /api; sitemap contributes /api and /.
    assert report.sources.get("html") == 1
    assert report.sources.get("robots") == 2
    assert report.candidate_count == 3
    assert report.parameter_count == 2


def test_discover_empty_documents_yield_nothing():
    report = discover_from_documents([], _scope_guard())
    assert report.candidate_count == 0
    assert report.parameter_count == 0
    assert report.refused == []


# ---------------------------------------------------------------------------
# stage planning / tool registration
# ---------------------------------------------------------------------------

def test_endpoint_discovery_registered_in_http_discovery_stage():
    assert stages.TOOL_TO_STAGE["endpoint_discovery"] == stages.HTTP_DISCOVERY
    assert stages.DEFAULT_TOOLS["endpoint_discovery"] is True
    assert "endpoint_discovery" in stages.STAGE_TOOLS[stages.HTTP_DISCOVERY]


def test_endpoint_discovery_plan_honest_enable_disable():
    assert any(t == "tool:endpoint_discovery" for t in stages.plan_tasks({}))
    assert not any(t == "tool:endpoint_discovery"
                   for t in stages.plan_tasks({"tools": {"endpoint_discovery": False}}))


def test_endpoint_discovery_disabled_skips_without_observations(session):
    scan = _make_scan(session, config={"tools": {"endpoint_discovery": False}})
    result = executions.execute_tool(session, scan, "endpoint_discovery",
                                     {"tools": {"endpoint_discovery": False}},
                                     None, {})
    assert result["status"] == "skipped"
    rows = session.query(Observation).filter(Observation.scan_id == scan.id).all()
    assert rows == []


# ---------------------------------------------------------------------------
# live fixture server integration (real evidence only)
# ---------------------------------------------------------------------------

class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, str, str]] = {}
    port_for_sitemap: int = 0

    def log_message(self, *args):  # silence test noise
        pass

    def do_GET(self):  # noqa: N802 (http.server API)
        status, ctype, body = self.routes.get(self.path, (404, "text/html", "<html>404</html>"))
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


def _fixture_server(body_overrides: dict | None = None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    html = (f'<!doctype html><html><head><title>fixture</title></head><body>'
            f'<a href="/api/items?page=1&sort=asc">items</a>'
            f'<a href="/api/items?page=2">more</a>'
            f'<a href="https://evil.example/steal">external</a>'
            f'<a href="mailto:admin@fixture.local">contact</a>'
            f'<form action="/search"></form>'
            f'<img src="/static/logo.png">'
            f'</body></html>')
    robots = (f"User-agent: *\nDisallow: /admin\nDisallow: /internal/?secret=1\n"
              f"Sitemap: {base_url}/sitemap.xml\n")
    sitemap = (f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
               f"<url><loc>{base_url}/</loc></url>"
               f"<url><loc>{base_url}/contact</loc></url></urlset>")

    routes = {
        "/": (200, "text/html", html),
        "/robots.txt": (200, "text/plain", robots),
        "/sitemap.xml": (200, "application/xml", sitemap),
    }
    routes.update(body_overrides or {})
    _FixtureHandler.routes = routes
    return server, base_url


@pytest.fixture
def fixture_server():
    server, base_url = _fixture_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, base_url
    server.shutdown()
    thread.join(timeout=5)


def test_endpoint_discovery_real_scan(session, fixture_server):
    server, base_url = fixture_server
    scan = _make_scan(session, target="127.0.0.1",
                      config={"tools": {"endpoint_discovery": True},
                              "endpoint_discovery": {"base_urls": [base_url]}})

    result = executions.execute_tool(session, scan, "endpoint_discovery",
                                     scan.scan_config, None, {})
    assert result["status"] == "success"

    rows = session.query(Observation).filter(
        Observation.scan_id == scan.id,
        Observation.tool_name == "endpoint_discovery").all()
    kinds = {r.kind for r in rows}
    assert "endpoint_discovery" in kinds
    assert "endpoint_candidate" in kinds

    candidates = {r.subject for r in rows if r.kind == "endpoint_candidate"}
    assert f"{base_url}/api/items" in candidates
    assert f"{base_url}/admin" in candidates       # from robots.txt Disallow
    assert f"{base_url}/internal/" in candidates      # trailing slash observed verbatim
    assert f"{base_url}/search" in candidates      # from form action
    assert f"{base_url}/static/logo.png" in candidates  # from img src
    assert f"{base_url}/contact" in candidates     # from sitemap loc
    assert f"{base_url}/" in candidates
    # The robots-declared sitemap URL is itself an observed endpoint.
    assert f"{base_url}/sitemap.xml" in candidates

    # Parameters observed on candidate endpoints only.
    parameters = {(r.data_json.get("parameter"), r.subject)
                  for r in rows if r.kind == "parameter_candidate"}
    assert ("page", f"{base_url}/api/items") in parameters
    assert ("sort", f"{base_url}/api/items") in parameters
    assert ("secret", f"{base_url}/internal/") in parameters
    assert ("page", f"{base_url}/internal/") not in parameters

    # Out-of-scope link observed but refused, never probed.
    refused = {r.subject for r in rows if r.kind == "endpoint_out_of_scope"}
    assert refused == {"https://evil.example/steal"}

    # Provenance columns are populated on every row.
    assert all(r.source == "native_discovery" for r in rows if r.kind in
               ("endpoint_candidate", "parameter_candidate", "endpoint_discovery"))
    assert all(r.status == "observed" for r in rows if r.kind != "endpoint_out_of_scope")

    # One honest execution + one ToolResult sidecar.
    assert session.query(ToolExecution).filter(
        ToolExecution.scan_id == scan.id,
        ToolExecution.tool == "endpoint_discovery",
        ToolExecution.status == "completed").count() == 1
    assert session.query(ToolResult).filter(
        ToolResult.scan_id == scan.id,
        ToolResult.tool_name == "endpoint_discovery").count() == 1


def test_endpoint_discovery_no_content_yields_no_candidates(session, fixture_server):
    server, base_url = fixture_server
    # Override every document to return 200 with an empty body: nothing to see.
    _FixtureHandler.routes = {
        "/": (200, "text/html", ""),
        "/robots.txt": (200, "text/plain", ""),
        "/sitemap.xml": (200, "application/xml", ""),
    }
    scan = _make_scan(session, target="127.0.0.1",
                      config={"tools": {"endpoint_discovery": True},
                              "endpoint_discovery": {"base_urls": [base_url]}})
    result = executions.execute_tool(session, scan, "endpoint_discovery",
                                     scan.scan_config, None, {})
    assert result["status"] == "success"
    rows = session.query(Observation).filter(
        Observation.scan_id == scan.id,
        Observation.tool_name == "endpoint_discovery").all()
    assert rows  # the honest summary exists
    assert not any(r.kind == "endpoint_candidate" for r in rows)
    assert not any(r.kind == "parameter_candidate" for r in rows)
    summary = next(r for r in rows if r.kind == "endpoint_discovery")
    assert summary.data_json["endpoint_candidates"] == 0


def test_endpoint_candidates_link_into_the_asset_graph(session, fixture_server):
    """Attack-surface persistence: candidates enter the asset graph, never
    as findings (they are hypotheses about the surface, not vulnerabilities)."""
    from app.orchestration import pipeline
    from database.models import Asset

    server, base_url = fixture_server
    scan = _make_scan(session, target="127.0.0.1",
                      config={"tools": {"endpoint_discovery": True},
                              "endpoint_discovery": {"base_urls": [base_url]}})
    assert executions.execute_tool(session, scan, "endpoint_discovery",
                                   scan.scan_config, None, {})["status"] == "success"

    pipeline._populate_asset_graph(session, scan)

    endpoints = session.query(Asset).filter(
        Asset.project_id == scan.project_id,
        Asset.type == "endpoint").all()
    values = {a.value for a in endpoints}
    assert f"{base_url}/api/items" in values
    assert f"{base_url}/admin" in values
    assert f"{base_url}/search" in values
    # A candidate endpoint asset is sourced from the discovery tool, not a finding.
    sourced = {a.source for a in endpoints}
    assert "endpoint_discovery" in sourced
    assert not any(a.type == "endpoint" and a.value.startswith("https://evil.example")
                   for a in endpoints)