"""Phase 14 operational hardening -- additive backend tests (real evidence only).

Covers the new operational surfaces without re-running the pipeline:

  * endpoint/parameter inventory enrichment: deterministic ``port`` (explicit
    URL port or scheme default) and honest per-endpoint ``assessed`` status
    derived only from persisted executed/validated/failed AssessmentTest rows,
  * the full typed timeline: every ScanEvent is returned with derived
    ``source``/``target``/``status``/``reference`` convenience fields,
  * operator "run now" on schedules (``trigger='run_now'`` attempt, refusal
    when the previous run is still live, scope + ownership enforcement),
  * the per-tool execution ledger in ``GET /tools/executions``.
"""
import datetime
import uuid

from app.discovery.inventory import endpoint_inventory
from app.discovery.parameters import parameter_inventory
from app.orchestration import events
from database.models import (
    AssessmentTest, Observation, Project, Scan, ScanAttempt, ScanSchedule,
    ToolExecution, User,
)


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def _make_scan(session, target="127.0.0.1", config=None):
    owner_id = f"p14-{uuid.uuid4().hex[:8]}"
    session.add(User(id=owner_id, email=f"{owner_id}@test.local", role="user"))
    session.commit()
    project = Project(name="p14", user_id=owner_id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="",
                scan_config=config)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _insert_observations(session, scan, rows):
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


def _api_scan(client, auth_headers, target):
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    resp = client.post("/scans", json={"target": target}, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["scan_id"]


def _add_assessment_test(session, scan, endpoint, status="executed",
                         test_id="injection.xss.reflected", category="xss"):
    test = AssessmentTest(
        scan_id=scan.id, test_id=test_id, name=test_id, category=category,
        status=status, endpoint=endpoint,
        reason="executed against observed endpoint",
    )
    session.add(test)
    session.commit()
    return test


# ---------------------------------------------------------------------------
# inventory enrichment: port + honest assessed status
# ---------------------------------------------------------------------------

def test_endpoint_inventory_explicit_and_default_ports(session):
    session.rollback()
    scan = _make_scan(session)
    _insert_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "http://127.0.0.1:8123/x?q=1",
         "source": "html"},
        {"kind": "endpoint_candidate", "subject": "https://in.example/a?page=1",
         "source": "html"},
        {"kind": "endpoint_candidate", "subject": "https://in.example:9443/b",
         "source": "html"},
    ])
    eps = endpoint_inventory(session, scan.id)
    by_url = {e["url"]: e for e in eps}
    # explicit URL port is used verbatim.
    assert by_url["http://127.0.0.1:8123/x"]["port"] == 8123
    assert by_url["https://in.example:9443/b"]["port"] == 9443
    # scheme default when none is explicit: deterministic, never guessed.
    assert by_url["https://in.example/a"]["port"] == 443
    assert all("assessment_statuses" in e for e in eps)
    assert all(e["assessed"] is False for e in eps)
    assert all(e["assessment_tests"] == 0 for e in eps)


def test_endpoint_inventory_assessed_from_executed_validation_failed_tests_only(session):
    session.rollback()
    scan = _make_scan(session)
    _insert_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://in.example/x?q=1",
         "source": "html"},
        {"kind": "endpoint_candidate", "subject": "https://in.example/other",
         "source": "html"},
    ])
    url = "https://in.example/x"
    _add_assessment_test(session, scan, url, status="executed")
    _add_assessment_test(session, scan, url, status="validated")

    eps = endpoint_inventory(session, scan.id)
    entry = next(e for e in eps if e["url"] == url)
    assert entry["assessed"] is True
    assert sorted(entry["assessment_statuses"]) == ["executed", "validated"]
    assert entry["assessment_tests"] == 2

    # planned / not_applicable / skipped / rejected tests are NOT evidence of
    # assessment -- the endpoint stays otherwise-marked, counts unaffected.
    _add_assessment_test(session, scan, url, status="planned", test_id="conf.skip")
    _add_assessment_test(session, scan, url, status="skipped", test_id="conf.skip2")
    _add_assessment_test(session, scan, url, status="not_applicable", test_id="conf.na")
    eps = endpoint_inventory(session, scan.id)
    entry = next(e for e in eps if e["url"] == url)
    assert entry["assessed"] is True
    assert sorted(entry["assessment_statuses"]) == ["executed", "validated"]
    assert entry["assessment_tests"] == 2

    # normalized aliasing matches (the planner persists normalized endpoints),
    # while a genuinely different endpoint never counts.
    _add_assessment_test(session, scan, "https://in.example/x/", status="executed",
                         test_id="conf.trailing")
    _add_assessment_test(session, scan, "https://in.example/other", status="executed",
                         test_id="conf.unrelated")
    eps = endpoint_inventory(session, scan.id)
    entry = next(e for e in eps if e["url"] == url)
    assert entry["assessment_tests"] == 3  # x/ normalizes onto x ; /other does not
    other = next(e for e in eps if e["url"] == "https://in.example/other")
    assert other["assessment_tests"] == 1


def test_parameter_inventory_assessed_flag_mirrors_endpoint(session):
    session.rollback()
    scan = _make_scan(session)
    _insert_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://in.example/search?q=1",
         "source": "html"},
        {"kind": "parameter_candidate", "subject": "https://in.example/search?q=1",
         "data": {"parameter": "q"}, "source": "html"},
    ])
    params = parameter_inventory(session, scan.id)
    assert params[0]["parameter"] == "q"
    assert params[0]["assessed"] is False
    assert "value" not in params[0]

    _add_assessment_test(session, scan, "https://in.example/search", status="executed")
    params = parameter_inventory(session, scan.id)
    assert params[0]["assessed"] is True


# ---------------------------------------------------------------------------
# full typed timeline with derived convenience fields
# ---------------------------------------------------------------------------

def test_timeline_expands_to_full_event_set_with_derived_fields(client, auth_headers, session):
    session.rollback()
    target = "ph14-tl.example.com"
    scan_id = _api_scan(client, auth_headers, target)
    scan = session.query(Scan).filter(Scan.id == scan_id).first()

    obs_ids = _insert_observations(session, scan, [
        {"kind": "endpoint_candidate", "subject": "https://ph14-tl.example.com/x?q=1",
         "source": "html"},
    ])
    events.emit_state(session, scan.id, "recon", "started recon")
    events.emit_observation(session, scan.id, obs_ids[0], "endpoint_candidate",
                            "https://ph14-tl.example.com/x", "endpoint_discovery")
    events.emit_endpoint_discovered(session, scan.id, obs_ids[0],
                                    "https://ph14-tl.example.com/x",
                                    "endpoint_candidate", "html")
    session.commit()

    body = client.get(f"/scans/{scan_id}/timeline", headers=auth_headers).json()
    items = body["items"]
    types = {i["type"] for i in items}
    # expanded beyond the Phase 12 surface-only subset.
    assert events.EVENT_STATE in types
    assert events.EVENT_OBSERVATION in types
    assert events.EVENT_ENDPOINT in types
    assert all(i["created_at"] for i in items)
    assert all("seq" in i for i in items)
    assert [i["seq"] for i in items] == sorted(i["seq"] for i in items)

    obs_item = next(i for i in items if i["type"] == events.EVENT_OBSERVATION)
    assert obs_item["source"] == "endpoint_discovery"  # tool key
    assert obs_item["target"] == "https://ph14-tl.example.com/x"  # subject key
    assert obs_item["reference"]["observation_id"] == obs_ids[0]

    ep_item = next(i for i in items if i["type"] == events.EVENT_ENDPOINT)
    assert ep_item["source"] == "html"
    assert ep_item["target"] == "https://ph14-tl.example.com/x"  # url key
    assert ep_item["reference"]["observation_id"] == obs_ids[0]


# ---------------------------------------------------------------------------
# schedules: operator run-now
# ---------------------------------------------------------------------------

def test_schedule_run_now_enqueues_with_run_now_trigger(client, auth_headers, session, monkeypatch):
    session.rollback()
    target = "ph14-run.example.com"
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    created = client.post("/schedules", headers=auth_headers, json={
        "target": target, "cadence": "daily", "interval": 1, "name": "run-now",
    }).json()
    schedule_id = created["id"]
    schedule = session.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    before_run = schedule.next_run_at

    enqueued_ids: list[int] = []
    fake = lambda scan_id, simulation=True, config=None, **kw: enqueued_ids.append(scan_id)
    monkeypatch.setattr("app.execution.schedule_loop.trigger_background_scan", fake)

    resp = client.post(f"/schedules/{schedule_id}/run", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "queued"
    scan_id = data["scan_id"]

    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    assert scan is not None and scan.source_schedule_id == schedule_id
    attempt = (session.query(ScanAttempt)
               .filter(ScanAttempt.scan_id == scan.id, ScanAttempt.trigger == "run_now")
               .first())
    assert attempt is not None and attempt.attempt_number == 1

    session.refresh(schedule)
    assert schedule.last_run_status == "queued"
    assert schedule.last_scan_id == scan.id
    assert schedule.last_run_at is not None
    # run-now never advances the recurrence clock.
    assert schedule.next_run_at == before_run

    # the just-created scan is still live -> no pile-up.
    refused = client.post(f"/schedules/{schedule_id}/run", headers=auth_headers)
    assert refused.status_code == 409


def test_schedule_run_now_out_of_scope_is_403(client, auth_headers, session, monkeypatch):
    session.rollback()
    target = "ph14-scope.example.com"
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    sid = client.post("/schedules", headers=auth_headers, json={
        "target": target, "cadence": "daily"}).json()["id"]

    row = session.query(ScanSchedule).filter(ScanSchedule.id == sid).first()
    row.target = "out-of-nowhere.example.org"  # drifts outside every scoped value
    session.commit()

    monkeypatch.setattr("app.execution.schedule_loop.trigger_background_scan", lambda **kw: None)
    resp = client.post(f"/schedules/{sid}/run", headers=auth_headers)
    assert resp.status_code == 403
    assert "scope" in resp.json()["detail"].lower()


def test_schedule_run_now_ownership_enforced(client, auth_headers, other_auth_headers, session):
    session.rollback()
    target = "ph14-owned.example.com"
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    sid = client.post("/schedules", headers=auth_headers, json={
        "target": target, "cadence": "daily"}).json()["id"]

    resp = client.post(f"/schedules/{sid}/run", headers=other_auth_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# per-tool execution ledger
# ---------------------------------------------------------------------------

def test_tools_executions_aggregates_real_rows_only(client, auth_headers, other_auth_headers, session):
    session.rollback()
    target = "ph14-tools.example.com"
    scan_id = _api_scan(client, auth_headers, target)

    # Delta-based accounting: the shared fixture user already owns past rows
    # from earlier suite files, so exact global totals are order-dependent.
    # We assert that THIS test's rows change the ledger by exactly the known
    # amounts -- deterministic no matter what ran before.
    before = client.get("/tools/executions", headers=auth_headers).json()
    b_totals = before["totals"]
    b_tools = {t["tool"]: t for t in before["tools"]}
    b_nmap = b_tools.get("nmap", {})
    b_nuclei = b_tools.get("nuclei", {})

    session.add(ToolExecution(scan_id=scan_id, stage="RECON", tool="nmap",
                              status="completed", parsed_observations=3,
                              finished_at=_now()))
    session.add(ToolExecution(scan_id=scan_id, stage="RECON", tool="nmap",
                              status="failed", parsed_observations=0,
                              finished_at=_now()))
    session.add(ToolExecution(scan_id=scan_id, stage="SCAN", tool="nuclei",
                              status="completed", parsed_observations=2,
                              finished_at=_now()))
    session.commit()

    body = client.get("/tools/executions", headers=auth_headers).json()
    tools = {t["tool"]: t for t in body["tools"]}
    assert tools["nmap"]["executions_total"] == (b_nmap.get("executions_total", 0) + 2)
    assert (tools["nmap"]["statuses"].get("completed", 0) ==
            (b_nmap.get("statuses", {}).get("completed", 0) + 1))
    assert (tools["nmap"]["statuses"].get("failed", 0) ==
            (b_nmap.get("statuses", {}).get("failed", 0) + 1))
    assert (tools["nuclei"]["observations_produced"] ==
            (b_nuclei.get("observations_produced", 0) + 2))
    assert body["totals"]["executions"] == b_totals["executions"] + 3
    assert (body["totals"]["observations_produced"] ==
            b_totals["observations_produced"] + 5)
    # known-but-never-executed tools appear with honest zero counts.
    assert any(t["executions_total"] == 0 for t in body["tools"])
    assert set(body["totals"]) >= {"completed", "failed", "timeout",
                                   "not_installed", "parse_failed", "skipped", "cancelled"}

    # a different user sees their own (empty) ledger, never another's.
    o_before = client.get("/tools/executions", headers=other_auth_headers).json()
    o_after = client.get("/tools/executions", headers=other_auth_headers).json()
    assert o_after["totals"]["executions"] == o_before["totals"]["executions"]