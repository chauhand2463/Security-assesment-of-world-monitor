"""Phase 6 finding-lifecycle, profiling, PoC and engine-candidate tests.

Verifies the state graph, immutable history, the profile/remediation mapping,
the PoC builder, and the engine's external-tool candidate sink (candidates are
never silently promoted to confirmed).
"""
import http.server
import uuid

import pytest

from app.assess import finding_lifecycle as lifecycle
from app.assess import profile
from app.assess.finding_lifecycle import InvalidTransition
from app.observations import types as obs_types
from database.models import FindingStatusHistory, Observation, Scan, User, Vulnerability


def _scan(session, email):
    from database.models import Project

    user = User(id=f"l-{uuid.uuid4().hex[:8]}", email=email, role="user")
    session.add(user)
    session.commit()
    project = Project(name="lifecycle", user_id=user.id, scope_json=["127.0.0.1"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="127.0.0.1", status="Completed", stage="completed")
    session.add(scan)
    session.commit()
    return user, project, scan


def _finding(session, scan, *, status=None, category="authorization", endpoint="http://app.local/admin"):
    finding = Vulnerability(
        scan_id=scan.id, title="Test finding", severity="High", description="d",
        state="NEW", category=category, endpoint=endpoint, http_method="GET",
        source_test="authorization.basic", source_tool="native_http", confidence="HIGH",
        status=status or lifecycle.STATUS_CONFIRMED,
    )
    session.add(finding)
    session.commit()
    lifecycle.record_initial(session, finding, reason="created for lifecycle test")
    session.commit()
    return finding


def test_initial_finding_is_confirmed_with_history(session):
    _user, _project, scan = _scan(session, "lf-init@test.local")
    finding = _finding(session, scan)
    assert finding.status == lifecycle.STATUS_CONFIRMED
    rows = session.query(FindingStatusHistory).filter(FindingStatusHistory.finding_id == finding.id).all()
    assert len(rows) == 1
    assert rows[0].from_status == "none"
    assert rows[0].to_status == "confirmed"
    assert rows[0].actor == "assessment_engine"


def test_transition_records_immutable_history(session):
    _user, _project, scan = _scan(session, "lf-trans@test.local")
    finding = _finding(session, scan, status=lifecycle.STATUS_CONFIRMED)
    lifecycle.transition(session, finding, lifecycle.STATUS_REMEDIATED,
                         actor="operator@test.local", reason="patch applied")
    session.commit()
    rows = session.query(FindingStatusHistory).filter(FindingStatusHistory.finding_id == finding.id).all()
    assert [r.to_status for r in rows] == ["confirmed", "remediated"]
    # Remediation sets resolved_at; history rows are never deleted.
    assert finding.resolved_at is not None
    assert len(rows) == 2


def test_remediation_transition_is_immutable_when_deleting_rebutal(session):
    _user, _project, scan = _scan(session, "lf-immut@test.local")
    finding = _finding(session, scan)
    lifecycle.transition(session, finding, lifecycle.STATUS_REMEDIATED, actor="a@test.local", reason="r1")
    session.commit()
    ids = [h.id for h in session.query(FindingStatusHistory).filter(FindingStatusHistory.finding_id == finding.id)]
    session.commit()
    assert len(ids) == 2  # initial + remediation


def test_illegal_transition_is_rejected_without_mutation(session):
    _user, _project, scan = _scan(session, "lf-illegal@test.local")
    finding = _finding(session, scan, status=lifecycle.STATUS_REJECTED)
    with pytest.raises(InvalidTransition):
        lifecycle.transition(session, finding, lifecycle.STATUS_ACCEPTED)
    session.rollback()
    session.refresh(finding)
    assert finding.status == lifecycle.STATUS_REJECTED


def test_candidate_can_be_promoted_to_confirmed_by_operator(session):
    _user, _project, scan = _scan(session, "lf-promote@test.local")
    finding = _finding(session, scan, status=lifecycle.STATUS_CANDIDATE)
    lifecycle.transition(session, finding, lifecycle.STATUS_CONFIRMED,
                         actor="operator@test.local", reason="validated manually")
    session.commit()
    assert finding.status == lifecycle.STATUS_CONFIRMED


def test_profile_resolves_component_and_remediation(session):
    _user, _project, scan = _scan(session, "lf-profile@test.local")
    finding = _finding(session, scan, category="authorization", endpoint="http://app.local/admin")
    prof = profile.profile_finding(category=finding.category, severity="High",
                                   source_test=finding.source_test, endpoint=finding.endpoint,
                                   source_tool=finding.source_tool)
    assert prof["affected_component"] == "authorization"
    assert "precaution" not in prof["impact_details"]["business"].lower()
    assert any(k in prof["remediation_details"] for k in ("technical_fix", "validation_steps"))
    assert "database" not in prof["affected_component"]


def test_profile_api_category_maps_to_backend_component():
    assert profile.resolve_component(category="xss", source_test="injection.xss.reflected",
                                     endpoint="http://app/search?q=1", source_tool="native_http") == "backend/api"
    assert profile.resolve_component(category="tls", source_test="tls", endpoint=None, source_tool=None) == "tls"
    assert profile.resolve_component(category="redirects", source_test="http.open_redirect",
                                     endpoint="http://app/redir", source_tool="native_http") == "frontend"


def test_poc_is_deterministic_and_safe(session):
    from app.assess.poc import build_poc, SAFETY_CONSTRAINTS

    _user, _project, scan = _scan(session, "lf-poc@test.local")
    finding = _finding(session, scan)
    poc = build_poc(session, finding)
    assert poc["request"]["method"] == "GET"
    assert "scope" in poc["steps_to_reproduce"].lower()
    assert "authorized" in SAFETY_CONSTRAINTS[0].lower()
    assert not any("rm " in c.lower() or "DROP" in c for c in __import__("json").dumps(poc))


def test_external_tool_observation_becomes_candidate_not_confirmed(session):
    import http.server
    import threading

    from app.assess import engine
    from database.models import Project, ToolResult

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    endpoint = f"{base}/search?q=hello"
    try:
        email = f"ext-{uuid.uuid4().hex[:8]}@test.local"
        user, project, scan = _scan(session, email)
        project.scope_json = ["127.0.0.1"]
        scan.target = f"127.0.0.1:{port}"
        session.commit()

        from app.observations.normalize import build_observation
        from app.assess import engine as engine_mod

        session.add(Observation(**build_observation(
            scan_id=scan.id, observation_type=obs_types.OBS_HTTP_RESPONSE, subject=endpoint,
            tool_name="native_http", source="http_client", user_id=user.id, target=scan.target,
            response={"status": 200, "url": endpoint, "headers": {"Content-Type": "text/html"}, "body": "hi"},
            discriminator={"endpoint": endpoint, "method": "GET"},
        )))
        # An external tool adapter reports a *potential* vulnerability.
        session.add(Observation(**build_observation(
            scan_id=scan.id, observation_type=obs_types.OBS_VULNERABILITY, subject=endpoint,
            tool_name="nuclei", source="external_tool", user_id=user.id, target=scan.target,
            data={"name": "Heartbleed-Signature", "template": "ssl/heartbleed", "severity": "High"},
        )))
        session.commit()

        result = engine_mod.run_assessment(session, scan, simulation=False,
                                           config={"active_testing": True, "assessment_engine": True})
        assert result["executed"] is True

        candidates = session.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id, Vulnerability.source_tool == "nuclei").all()
        assert candidates
        assert all(c.status == lifecycle.STATUS_CANDIDATE for c in candidates)
        # Phase 10.7: external candidates now live in the SAME fingerprint
        # namespace as native findings (no more "external:…" keys).
        from app.http.fingerprints import host_of
        from app.observations.fingerprint import finding_fingerprint

        for c in candidates:
            assert c.dedup_key == finding_fingerprint(
                c.category or "external_tool", host_of(c.endpoint or c.target) or scan.target,
                c.endpoint, None)
            assert "external:" not in (c.dedup_key or "")
            assert c.fingerprint == c.dedup_key

        # The report aggregates must see the candidate count.
        from app.assess import summary as summary_mod
        agg = summary_mod.aggregate(session, scan)
        assert agg["total_candidates"] >= 1
    finally:
        server.shutdown()
        server.server_close()


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qsl, urlsplit

        value = dict(parse_qsl(urlsplit(self.path).query)).get("q", "")
        body = f"<html><body>result: {value}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass