"""Phase 12 slice 3 -- continuous-assessment scheduling tests.

Covers the recurrence primitives, the tick's scan creation path (a fresh
``Scan`` with ``source_schedule_id`` + a ``trigger='schedule'`` attempt), and
the schedules CRUD API with scope/ownership enforcement.
"""
import datetime
import uuid

import pytest

from app.execution.schedule_loop import next_run_at, scheduler_tick
from database.models import Scan, ScanAttempt, ScanSchedule, User


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


# ---------------------------------------------------------------------------
# recurrence primitives
# ---------------------------------------------------------------------------

def test_next_run_at_derivation():
    after = datetime.datetime(2026, 9, 24, 12, 0, 0)
    assert next_run_at("hourly", 1, after) == after + datetime.timedelta(hours=1)
    assert next_run_at("daily", 7, after) == after + datetime.timedelta(days=7)
    assert next_run_at("weekly", 2, after) == after + datetime.timedelta(weeks=2)
    assert next_run_at("daily", 0, after) == after + datetime.timedelta(days=1)


# ---------------------------------------------------------------------------
# tick: due schedule -> fresh scan row via the normal enqueue path
# ---------------------------------------------------------------------------

def test_scheduler_tick_creates_scan_with_schedule_provenance(client, auth_headers, session, monkeypatch):
    session.rollback()
    target = "sch-tick.example.com"
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    resp = client.post("/schedules", headers=auth_headers, json={
        "target": target, "cadence": "daily", "interval": 1, "name": "daily sweep",
    })
    assert resp.status_code == 200, resp.text
    schedule_id = resp.json()["id"]

    schedule = session.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    schedule.next_run_at = _now() - datetime.timedelta(minutes=5)
    session.commit()

    enqueued_ids: list[int] = []
    fake = lambda scan_id, simulation=True, config=None, **kw: enqueued_ids.append(scan_id)
    monkeypatch.setattr("app.execution.schedule_loop.trigger_background_scan", fake)

    count = scheduler_tick(session)
    assert count == 1

    scheduled = session.query(Scan).filter(Scan.source_schedule_id == schedule_id).all()
    assert len(scheduled) == 1
    scan = scheduled[0]
    assert scan.schedule_cadence == "daily"
    assert scan.assessment_type == "custom_target"

    attempt = (session.query(ScanAttempt)
               .filter(ScanAttempt.scan_id == scan.id, ScanAttempt.trigger == "schedule")
               .first())
    assert attempt is not None and attempt.attempt_number == 1

    session.refresh(schedule)
    assert schedule.last_run_status == "queued"
    assert schedule.last_scan_id == scan.id
    assert schedule.next_run_at > _now()
    assert enqueued_ids == [scan.id]


def test_scheduler_tick_skips_schedule_whose_last_scan_is_live(session):
    from database.models import Project
    owner_id = f"sch-{uuid.uuid4().hex[:8]}"
    session.add(User(id=owner_id, email=f"{owner_id}@test.local", role="user"))
    session.commit()
    project = Project(name="sch-live", user_id=owner_id, scope_json=["live.example.com"])
    session.add(project)
    session.commit()

    schedule = ScanSchedule(
        user_id=owner_id, project_id=project.id, target="live.example.com",
        cadence="daily", interval=1, enabled=True,
        next_run_at=_now() - datetime.timedelta(minutes=5),
        last_run_status="queued", last_scan_id=None,
    )
    session.add(schedule)
    session.commit()
    session.refresh(schedule)

    live_scan = Scan(project_id=project.id, target=schedule.target,
                     status="Running", stage="running", logs="",
                     source_schedule_id=schedule.id)
    session.add(live_scan)
    session.commit()
    schedule.last_scan_id = live_scan.id
    session.commit()

    count = scheduler_tick(session)
    assert count == 0  # previous execution still live -> no pile-up


def test_user_schema_model_is_importable():
    import database.models as m
    assert hasattr(m, "ScanSchedule")
    assert "scan_schedules" in m.Base.metadata.tables


# ---------------------------------------------------------------------------
# schedules API: CRUD + ownership + scope
# ---------------------------------------------------------------------------

def test_schedules_crud_and_disable(client, auth_headers, session):
    target = "sch-crud.example.com"
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    created = client.post("/schedules", headers=auth_headers, json={
        "target": target, "cadence": "weekly", "interval": 2, "name": "weekly",
    }).json()
    sid = created["id"]
    assert created["cadence"] == "weekly" and created["enabled"] is True
    assert created["next_run_at"]

    listed = client.get("/schedules", headers=auth_headers).json()
    assert any(s["id"] == sid for s in listed)

    updated = client.patch(f"/schedules/{sid}", headers=auth_headers,
                           json={"enabled": False}).json()
    assert updated["enabled"] is False

    deleted = client.delete(f"/schedules/{sid}", headers=auth_headers).json()
    assert deleted["disabled"] is True

    scans = client.get(f"/schedules/{sid}/scans", headers=auth_headers).json()
    assert scans == []


def test_schedule_scope_rejected_outside_project_scope(client, auth_headers):
    resp = client.post("/schedules", headers=auth_headers, json={
        "target": "not-in-scope.example.org", "cadence": "daily",
    })
    assert resp.status_code == 403


def test_schedule_ownership_enforced(client, auth_headers, other_auth_headers):
    target = "sch-owned.example.com"
    from conftest import add_scope
    add_scope(client, auth_headers, target)
    sid = client.post("/schedules", headers=auth_headers, json={
        "target": target, "cadence": "daily"}).json()["id"]

    assert client.get("/schedules", headers=other_auth_headers).json() == []
    assert client.patch(f"/schedules/{sid}", headers=other_auth_headers,
                        json={"enabled": False}).status_code == 404
    assert client.delete(f"/schedules/{sid}", headers=other_auth_headers).status_code == 404
    assert client.get(f"/schedules/{sid}/scans", headers=other_auth_headers).status_code == 404