"""Phase 7 pipeline end-to-end (hermetic).

``orchestrate_scan_phase7`` is exercised with every external dependency stubbed:
legacy CLI runners return deterministic empty successes/failures, adapters return
empty completed runs, stdlib probes are injected, and the Phase 5 engine's HTTP
client is replaced by an offline stub (URLError-shaped responses, status 0) so
the engine logic still runs without ever opening a socket.

Assertions target the *honest trail*: 13 completed stages, one ToolExecution row
per tool, findings derived only from persisted observations, typed events,
the advisory record and the terminal state machine.
"""

import types
import uuid

import pytest

from app.orchestration import pipeline
from app.orchestration import state as SM
from app.tools import scanner_tools
from database.connection import SessionLocal
from database.models import (MLInference, Observation, Project, Scan, ScanEvent,
                             ScanStage, ToolExecution, ToolResult, User,
                             Vulnerability)


# ---------------------------------------------------------------------------
# hermetic stubs
# ---------------------------------------------------------------------------
def _make_scan(session, target="example.com"):
    owner = User(id=f"p7e2e-{uuid.uuid4().hex[:8]}", email=f"p7e2e-{uuid.uuid4().hex[:8]}@test.local",
                 role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p7e2e", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def _inject_probes(monkeypatch):
    import app.tools.real_probes as real_probes

    def fake_dns(host, **kw):
        return {
            "status": "success",
            "observations": [{
                "kind": "dns_record", "subject": host,
                "data": {"host": host, "ip": "93.184.216.34", "family": "A"},
                "raw": f"{host} -> A 93.184.216.34",
            }],
            "log": f"[real_dns] resolved {host}",
        }

    def fake_tcp(host, **kw):
        return {
            "status": "success",
            "observations": [{
                "kind": "tcp_open", "subject": host,
                "data": {"host": host, "port": 443, "state": "open"},
                "raw": f"{host}:443 open",
            }],
            "log": f"[real_tcp] open ports [443] on {host}",
        }

    def fake_http(url, **kw):
        scheme = url.split("://", 1)[0]
        if scheme == "https":
            obs = [
                {"kind": "http_response", "subject": url, "data": {
                    "url": url, "scheme": scheme, "status_code": 200, "server": "nginx",
                    "version_hint": None, "title": "Acme", "has_csp": False,
                    "has_hsts": True, "has_xcto": False, "has_xframe": True,
                    "headers": {}, "body_snippet": "jquery-1.12.4.min.js",
                }, "raw": f"GET {url} -> 200 [nginx]"},
                {"kind": "body_match", "subject": url, "data": {
                    "url": url, "match": "jquery_version", "version": "1.12.4"},
                    "raw": f"GET {url} body references jQuery 1.12.4"},
            ]
        else:
            obs = [{"kind": "http_error", "subject": url, "data": {
                "url": url, "scheme": scheme, "error": "Connection refused"},
                "raw": f"GET {url} failed: Connection refused"}]
        return {"status": "success", "observations": obs, "log": f"[real_http] GET {url}"}

    monkeypatch.setattr(real_probes, "dns_probe", fake_dns)
    monkeypatch.setattr(real_probes, "tcp_probe", fake_tcp)
    monkeypatch.setattr(real_probes, "http_probe", fake_http)


def _inject_cli(monkeypatch, override=None):
    empty = {
        "subfinder": ("success", {"subdomains": []}),
        "assetfinder": ("success", {"subdomains": []}),
        "dnsx": ("success", {"resolved": []}),
        "gau": ("success", {"urls": []}),
        "whatweb": ("success", {"techs": [], "technologies": []}),
        "nuclei": ("success", {"vulnerabilities": []}),
    }
    if override:
        empty.update(override)

    def _fn(tool):
        status, extra = empty[tool]
        return dict({"status": status, "log": f"[{tool}] stubbed"}, **extra)

    monkeypatch.setattr(
        pipeline.executions, "_LEGACY_RUNNERS",
        {tool: (lambda target, _t=tool: _fn(_t)) for tool in empty})


class _OfflineResult:
    def __init__(self, status=None):
        self.status = status or scanner_tools.STATE_COMPLETED
        self.observations = []
        self.command = ["stub"]
        self.exit_code = 0
        self.error = None
        self.duration_ms = 1
        self.raw_output = "[stub] completed with no observations"


class _OfflineAdapter:
    def run(self, target, simulation=False, options=None, cancel_check=None):
        return _OfflineResult()

    def available(self):
        return True


def _inject_adapters(monkeypatch):
    monkeypatch.setattr(pipeline.executions, "get_adapter",
                        lambda tool: _OfflineAdapter() if tool in ("nmap", "httpx") else None)


class _OfflineHTTPResponse:
    def __init__(self, status=0, error="stubbed offline", url="http://offline"):
        import datetime
        self.status = status
        self.url = url
        self.headers = {}
        self.body = ""
        self.elapsed_ms = 0.0
        self.redirect_chain = []
        self.content_type = None
        self.tls = None
        self.error = error
        self.request = {"method": "GET", "url": url}


class _OfflineClient:
    """Drop-in for SafeHttpClient: every request fails without a socket.

    Mirrors the real client's URLError path (status 0, error set) so tests that
    treat refused connections as evidence keep behaving offline and offline.
    """
    def __init__(self, scope_guard, limits=None, *, capture_tls=False):
        self.scope_guard = scope_guard
        self.limits = limits
        self.capture_tls = capture_tls
        self.requests_made = 0

    def reset_test_counter(self):
        pass

    def request(self, method, url, **kw):
        self.requests_made += 1
        self.scope_guard(url)
        return _OfflineHTTPResponse(url=url)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, body=None, **kw):
        return self.request("POST", url, **kw)

    def probe_callback(self, url, **kw):
        return self.request("GET", url)


def _inject_offline_http(monkeypatch):
    monkeypatch.setattr("app.http.client.SafeHttpClient", _OfflineClient)


def _hermetic(monkeypatch, cli_override=None):
    _inject_probes(monkeypatch)
    _inject_cli(monkeypatch, cli_override)
    _inject_adapters(monkeypatch)
    _inject_offline_http(monkeypatch)


def _read(scan_id, fn):
    db = SessionLocal()
    try:
        return fn(db, db.query(Scan).filter(Scan.id == scan_id).first())
    finally:
        db.close()


# ---------------------------------------------------------------------------
# happy path: everything completes
# ---------------------------------------------------------------------------
def test_phase7_pipeline_completes_with_honest_trail(monkeypatch, session):
    _hermetic(monkeypatch)
    scan_id = _make_scan(session)
    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    def _assert(db, scan):
        assert scan.state == SM.COMPLETED
        assert scan.status == "Completed"
        assert scan.stage == "completed"
        assert scan.coverage is not None

        progress = scan.progress or {}
        assert progress["execution_platform"] == "phase7"
        assert progress["completed_tasks"] == progress["total_tasks"]
        assert progress["failed_tasks"] == 0
        assert progress["percent"] == 100.0

        stages = db.query(ScanStage).filter(ScanStage.scan_id == scan_id).order_by(ScanStage.id).all()
        assert len(stages) == 13
        assert all(s.status == "completed" for s in stages)
        assert [s.name for s in stages][0] == "PRECHECK"

        executions = db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all()
        assert len(executions) == 12  # 3 probes + endpoint_discovery + 6 legacy + nmap + httpx
        assert {e.status for e in executions} == {"completed"}

        tool_results = db.query(ToolResult).filter(ToolResult.scan_id == scan_id).all()
        assert len(tool_results) == 13  # 12 planned tools + native_assessment (Phase 5 engine)
        assert all(t.status == "Completed" for t in tool_results)

        obs = db.query(Observation).filter(Observation.scan_id == scan_id).all()
        kinds = {o.kind for o in obs}
        assert {"dns_record", "tcp_open", "http_response", "body_match"} <= kinds

        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        rules = {f.rule_id for f in findings}
        assert {"missing-security-header", "outdated-jquery"} <= rules
        for f in findings:
            assert f.evidence_observation_ids, "every finding must cite evidence observations"

        events = db.query(ScanEvent).filter(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id).all()
        assert events
        types_seen = {e.event_type for e in events}
        assert {"state", "stage", "tool", "preflight", "coverage", "done"} <= types_seen
        done = [e.data for e in events if e.event_type == "done"]
        assert done and done[-1].get("state") == SM.COMPLETED
        seqs = [e.seq for e in events]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)

        ml = db.query(MLInference).filter(MLInference.scan_id == scan_id).all()
        assert ml and ml[0].status == "advisory_only" and ml[0].model_name is None

        report = scan.reports[0]
        payload = report.json_content
        assert payload["findings"]
        assert payload["execution_platform_version"] == "phase7"
        assert payload["execution_trail"]["total_tasks"] == 25
        assert len(payload["stages"]) == 13
        assert len(payload["executions"]) == 12
        assert payload["ml_advisory"]
        assert payload["preflight"]["runnable"] is True
        assert scan.preflight_json["missing"]  # subfinder may present; others absent -> honest
    _read(scan_id, _assert)


# ---------------------------------------------------------------------------
# gaps: a tool timeout -> completed_with_gaps, never a fabricated success
# ---------------------------------------------------------------------------
def test_phase7_pipeline_records_gaps_when_a_tool_times_out(monkeypatch, session):
    _hermetic(monkeypatch, cli_override={
        "subfinder": (scanner_tools.STATE_TIMEOUT, {"error": "stubbed timeout"}),
    })
    scan_id = _make_scan(session)
    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    def _assert(db, scan):
        assert scan.state == SM.COMPLETED_WITH_GAPS
        assert scan.status == "Partially Completed"
        progress = scan.progress or {}
        assert progress["failed_tasks"] == 1
        assert progress["percent"] < 100.0
        sub = db.query(ToolExecution).filter(
            ToolExecution.scan_id == scan_id, ToolExecution.tool == "subfinder").one()
        assert sub.status == "timeout"
        sub_result = db.query(ToolResult).filter(
            ToolResult.scan_id == scan_id, ToolResult.tool_name == "subfinder").one()
        assert sub_result.status == scanner_tools.STATE_TIMEOUT
        done = db.query(ScanEvent).filter(
            ScanEvent.scan_id == scan_id, ScanEvent.event_type == "done").all()
        assert done and done[-1].data.get("state") == SM.COMPLETED_WITH_GAPS
    _read(scan_id, _assert)


# ---------------------------------------------------------------------------
# blocked: an unsafe target must never run tools
# ---------------------------------------------------------------------------
def test_phase7_pipeline_blocks_an_unsafe_target(monkeypatch, session):
    _hermetic(monkeypatch)
    scan_id = _make_scan(session, target="")
    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    def _assert(db, scan):
        assert scan.state == SM.BLOCKED
        assert scan.status == "Blocked"
        assert db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).count() == 0
        assert db.query(Observation).filter(Observation.scan_id == scan_id).count() == 0
        assert db.query(ToolResult).filter(ToolResult.scan_id == scan_id).count() == 0
        assert scan.error
    _read(scan_id, _assert)