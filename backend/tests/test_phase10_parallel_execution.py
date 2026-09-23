"""Phase 10.3 — parallel execution scheduler tests.

The scheduler keeps the plan honest under concurrency:
  * ``max_parallel_tools`` is a real, bounded concurrency (clamped 1..8, default
    1 = sequential),
  * ``execute_batch`` returns one result per tool in plan order and isolates a
    worker crash (never aborts siblings, never fabricates success),
  * cancellation is honored per scan and aborts the remaining plan,
  * the pipeline driver records one ``ScanExecution`` row whose strategy and
    counters reflect what really happened.
"""

import time
import threading
import uuid

import pytest

from conftest import add_scope
from app.execution.scheduler import (
    DEFAULT_MAX_PARALLEL,
    MAX_PARALLEL_LIMIT,
    execute_batch,
    group_plan,
    max_parallel_tools,
)
from app.orchestration import pipeline
from app.orchestration import state as SM
from app.tools import scanner_tools
from app.workers.tasks import ScanCancelled
from database.connection import SessionLocal
from database.models import Project, Scan, ScanExecution, User


def _make_scan(session, target="example.com", config=None):
    owner = User(id=f"p10p-{uuid.uuid4().hex[:8]}",
                 email=f"p10p-{uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p10p", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="",
                scan_config=config)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


# ---------------------------------------------------------------------------
# bound semantics
# ---------------------------------------------------------------------------
def test_max_parallel_default_is_sequential():
    assert DEFAULT_MAX_PARALLEL == 1
    assert max_parallel_tools(None) == 1
    assert max_parallel_tools({}) == 1
    assert max_parallel_tools({"max_parallel_tools": None}) == 1


def test_max_parallel_clamps_within_bounds():
    assert max_parallel_tools({"max_parallel_tools": 0}) == 1
    assert max_parallel_tools({"max_parallel_tools": -3}) == 1
    assert max_parallel_tools({"max_parallel_tools": 3}) == 3
    assert max_parallel_tools({"max_parallel_tools": 999}) == MAX_PARALLEL_LIMIT
    assert max_parallel_tools({"max_parallel_tools": "garbage"}) == 1
    assert max_parallel_tools({"max_parallel_tools": 2.7}) == 2


# ---------------------------------------------------------------------------
# plan grouping mirrors plan_tasks exactly
# ---------------------------------------------------------------------------
def test_group_plan_mirrors_plan_tasks():
    from app.orchestration.stages import plan_tasks

    config = {}
    flat = plan_tasks(config)
    assert sum(len(g.get("tools") or ()) for g in group_plan(config)) == \
        sum(1 for t in flat if t.startswith("tool:"))
    # Stage order is preserved and every stage appears exactly once.
    stages = [g["stage"] for g in group_plan(config)]
    assert stages == sorted(dict.fromkeys(stages), key=stages.index)
    # Tools map back to their stage in plan order.
    rebuilt = []
    for g in group_plan(config):
        rebuilt.append(f"stage:{g['stage']}")
        rebuilt.extend(f"tool:{t}" for t in g["tools"])
    assert rebuilt == flat


# ---------------------------------------------------------------------------
# execute_batch: sequential default keeps exception semantics
# ---------------------------------------------------------------------------
def test_execute_batch_sequential_preserves_order(session):
    scan = _make_scan(session, config={"max_parallel_tools": 1})
    calls = []

    def runner(db, scan_obj, tool, config, job, state):
        calls.append(tool)
        return {"tool": tool, "status": "success", "log": f"ran {tool}"}

    tools = ["subfinder", "nmap", "httpx", "nuclei"]
    results = execute_batch(session, scan, {"max_parallel_tools": 1}, None, {},
                            tools, runner=runner)
    assert calls == tools
    assert [r["tool"] for r in results] == tools
    assert all(r["status"] == "success" for r in results)


def test_execute_batch_sequential_allows_worker_exception(session):
    # In sequential mode exceptions propagate exactly as the Phase 7 driver
    # did: there is no sibling isolation to preserve.
    scan = _make_scan(session, config={"max_parallel_tools": 1})

    def runner(db, scan_obj, tool, config, job, state):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        execute_batch(session, scan, {"max_parallel_tools": 1}, None, {},
                      ["nmap"], runner=runner)


# ---------------------------------------------------------------------------
# execute_batch: parallel path bounds real concurrency
# ---------------------------------------------------------------------------
def test_execute_batch_parallel_respects_bound_and_isolation(session):
    scan = _make_scan(session, config={"max_parallel_tools": 3})
    lock = threading.Lock()
    active = [0]
    max_active = [0]

    def runner(db, scan_obj, tool, config, job, state):
        with lock:
            active[0] += 1
            max_active[0] = max(max_active[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        if tool.startswith("fail:"):
            raise ValueError(f"worker crash for {tool}")
        return {"tool": tool, "status": "success"}

    tools = ["subfinder", "fail:assetfinder", "dnsx", "nmap", "fail:httpx", "nuclei"]
    results = execute_batch(session, scan, {"max_parallel_tools": 3}, None, {},
                            tools, runner=runner)
    # Bounded real concurrency.
    assert max_active[0] <= 3
    assert max_active[0] >= 2  # the bound was actually useful
    # Order preserved, one result per tool.
    assert [r["tool"] for r in results] == tools
    # Failed workers isolated: siblings succeeded, failures are honest.
    by_tool = {r["tool"]: r for r in results}
    assert by_tool["subfinder"]["status"] == "success"
    assert by_tool["fail:assetfinder"]["status"] == scanner_tools.STATE_EXECUTION_FAILED
    assert by_tool["nmap"]["status"] == "success"
    assert by_tool["fail:httpx"]["status"] == scanner_tools.STATE_EXECUTION_FAILED
    assert by_tool["nuclei"]["status"] == "success"


def test_execute_batch_parallel_cancellation_aborts(session):
    scan = _make_scan(session, config={"max_parallel_tools": 3})
    started = []

    def runner(db, scan_obj, tool, config, job, state):
        started.append(tool)
        raise ScanCancelled("operator cancelled")

    with pytest.raises(ScanCancelled):
        execute_batch(session, scan, {"max_parallel_tools": 3}, None, {},
                      ["subfinder", "nmap", "httpx"], runner=runner)
    # Cancellation surfaced: it never degraded into a fabricated success.
    assert started


def test_execute_batch_single_tool_not_parallel(session):
    scan = _make_scan(session, config={"max_parallel_tools": 8})
    calls = []

    def runner(db, scan_obj, tool, config, job, state):
        calls.append(tool)
        return {"tool": tool, "status": "success"}

    results = execute_batch(session, scan, {"max_parallel_tools": 8}, None, {},
                            ["nmap"], runner=runner)
    assert [r["tool"] for r in results] == ["nmap"]
    assert calls == ["nmap"]


# ---------------------------------------------------------------------------
# pipeline end-to-end with an execution record
# ---------------------------------------------------------------------------
def test_phase7_pipeline_records_sequential_execution(monkeypatch, session):
    from test_phase7_pipeline_end_to_end import _hermetic

    _hermetic(monkeypatch)
    scan = _make_scan(session, config=None)
    pipeline.orchestrate_scan_phase7(scan.id, simulation=False)

    db = SessionLocal()
    try:
        row = (db.query(ScanExecution)
               .filter(ScanExecution.scan_id == scan.id)
               .order_by(ScanExecution.id.desc()).first())
        assert row is not None
        assert row.strategy == "sequential"
        assert row.max_parallel_tools == 1
        assert row.status == "completed"
        assert row.planned_tools >= 1
        assert row.completed_tools == row.planned_tools
        assert row.failed_tools == 0
        assert row.duration_ms is not None
        assert row.plan is not None and isinstance(row.plan, list)
        # The recorded plan reflects the real plan_tasks structure.
        from app.orchestration.stages import plan_tasks
        flat = [f"stage:{g['stage']}" for g in row.plan]
        assert flat == [t for t in plan_tasks(scan.scan_config or {}) if t.startswith("stage:")]
    finally:
        db.close()


def test_phase7_pipeline_records_parallel_execution(monkeypatch, session):
    from test_phase7_pipeline_end_to_end import _hermetic

    _hermetic(monkeypatch)
    scan = _make_scan(session, config={"max_parallel_tools": 3})
    pipeline.orchestrate_scan_phase7(scan.id, simulation=False, config={"max_parallel_tools": 3})

    def _assert(db, scan_obj):
        assert scan_obj.state == SM.COMPLETED
        row = (db.query(ScanExecution)
               .filter(ScanExecution.scan_id == scan_obj.id)
               .order_by(ScanExecution.id.desc()).first())
        assert row is not None
        assert row.strategy == "parallel"
        assert row.max_parallel_tools == 3
        assert row.status == "completed"
        assert row.planned_tools == row.completed_tools == row.started_tools
        assert row.failed_tools == 0
        assert row.duration_ms is not None
        # Every planned tool was accounted for in the honest record.
        assert row.completed_tools + row.failed_tools + row.skipped_tools >= 1
        assert row.plan and len(row.plan) >= 1
    _read_db(scan.id, _assert)


def _read_db(scan_id, fn):
    db = SessionLocal()
    try:
        return fn(db, db.query(Scan).filter(Scan.id == scan_id).first())
    finally:
        db.close()


# ---------------------------------------------------------------------------
# execution-plan API
# ---------------------------------------------------------------------------
def test_execution_plan_endpoint_reports_real_record(client, auth_headers, monkeypatch):
    from test_phase7_pipeline_end_to_end import _hermetic

    _hermetic(monkeypatch)
    add_scope(client, auth_headers, "example.com")
    resp = client.post("/scans", json={
        "target": "example.com",
        "assessment_type": "custom_target",
        "authorization_acknowledged": True,
        "max_parallel_tools": 3,
    }, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["scan_id"]

    # Before a run the record does not exist; the plan is still reported from
    # the configured scheduler (group_plan), never fabricated.
    pre = client.get(f"/scans/{scan_id}/execution-plan", headers=auth_headers).json()
    assert pre["exists"] is False
    assert pre["max_parallel_tools"] == 3
    assert pre["plan"] and sum(len(g.get("tools") or ()) for g in pre["plan"]) >= 1

    pipeline.orchestrate_scan_phase7(scan_id, simulation=False,
                                     config={"max_parallel_tools": 3})
    post = client.get(f"/scans/{scan_id}/execution-plan", headers=auth_headers).json()
    assert post["exists"] is True
    assert post["strategy"] == "parallel"
    assert post["status"] == "completed"
    assert post["max_parallel_tools"] == 3
    assert post["planned_tools"] == post["completed_tools"]
    assert post["failed_tools"] == 0
    assert post["duration_ms"] is not None
    assert post["started_at"] is not None and post["finished_at"] is not None
    assert [g["stage"] for g in post["plan"]]