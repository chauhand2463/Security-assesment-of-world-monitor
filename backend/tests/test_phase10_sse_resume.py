"""Phase 10.8 — SSE typed cursor + `Last-Event-ID` resume (gap G5).

The `/scans/{id}/events` endpoint streams the persisted ``scan_events`` ledger
as a typed cursor: every event carries an ``id:`` line equal to the ScanEvent
row id, and a reconnecting client sends ``Last-Event-ID`` to resume exactly
where it stopped.  For legacy/backfilled scans with no event ledger the
endpoint keeps the original diff-based synthesis, so the wire vocabulary is
unchanged (stage/tool/progress/finding/done/error).
"""
import json
import uuid

from database.connection import SessionLocal
from database.models import Project, Scan, ScanEvent, User, Vulnerability


def _owner(session):
    user = session.query(User).filter(User.email == "owner@test.local").first()
    if user is None:
        user = User(id=f"p108-{uuid.uuid4().hex[:8]}",
                    email="owner@test.local", role="user")
        session.add(user)
        session.commit()
    return user


def _own_scan(session, stage="Running", events=None):
    owner = _owner(session)
    project = Project(name="p108", user_id=owner.id, scope_json=["resume.example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="resume.example.com",
                status="Completed", stage=stage, coverage=100.0, security_score=88.0)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    for i, (etype, data) in enumerate(events or [], start=1):
        session.add(ScanEvent(scan_id=scan.id, event_type=etype, data=data, seq=i))
    session.commit()
    return scan.id


def _read_sse_payloads(lines):
    payloads = []
    for line in lines:
        if line.startswith("data: "):
            payloads.append(json.loads(line[len("data: "):]))
    return payloads


def _read_sse_ids(lines):
    ids = []
    for i, line in enumerate(lines):
        if line.startswith("id: "):
            ids.append(int(line[len("id: "):]))
    return ids


def _sse_lines(response):
    return list(response.iter_lines())


# ---------------------------------------------------------------------------
# typed cursor: every emitted event carries w t he scan_event id
# ---------------------------------------------------------------------------
def test_events_stream_is_typed_cursor_over_ledger(client, auth_headers):
    session = SessionLocal()
    try:
        scan_id = _own_scan(
            session,
            events=[
                ("stage", {"stage": "RECON", "status": "completed"}),
                ("stage", {"stage": "SERVICE_SCAN", "status": "started"}),
                ("tool", {"tool": "nmap", "status": "completed", "attempt": 1}),
                ("coverage", {"coverage_percent": 100.0, "completed": 8, "total": 8}),
                ("done", {"state": "COMPLETED"}),
            ],
        )
        session.close()
    finally:
        session.close()

    with client.stream("GET", f"/scans/{scan_id}/events", headers=auth_headers) as stream:
        lines = _sse_lines(stream)
    payloads = _read_sse_payloads(lines)
    ids = _read_sse_ids(lines)

    assert len(payloads) == len(ids) == 5
    # ids are exactly the ledger row ids, ascending
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    # wire vocabulary unchanged
    assert [p["type"] for p in payloads] == ["stage", "stage", "tool", "progress", "done"]
    # only events the live dashboard consumes appear (internals hidden)
    for p in payloads:
        assert p["type"] in {"stage", "tool", "progress", "finding", "done", "error"}
    assert payloads[-1]["type"] == "done"
    assert payloads[-1]["status"] == "Completed"
    assert payloads[-1]["coverage"] == 100.0


# ---------------------------------------------------------------------------
# Last-Event-ID => exact resume, no re-delivery, no gaps
# ---------------------------------------------------------------------------
def test_last_event_id_resumes_exactly_after_cursor(client, auth_headers):
    session = SessionLocal()
    try:
        scan_id = _own_scan(
            session,
            events=[
                ("stage", {"stage": "RECON", "status": "completed"}),
                ("tool", {"tool": "subfinder", "status": "completed", "attempt": 1}),
                ("tool", {"tool": "httpx", "status": "completed", "attempt": 1}),
                ("done", {"state": "COMPLETED"}),
            ],
        )
        row_ids = [e.id for e in session.query(ScanEvent)
                   .filter(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id).all()]
        session.close()
        # sanity: ledger ids are 1..4 in this isolated test db
        assert len(row_ids) >= 4
        resume_at = row_ids[1]  # client already delivered the first two events
    finally:
        session.close()

    with client.stream(
        "GET", f"/scans/{scan_id}/events",
        headers={**auth_headers, "Last-Event-ID": str(resume_at)},
    ) as stream:
        lines = _sse_lines(stream)
    payloads = _read_sse_payloads(lines)
    ids = _read_sse_ids(lines)

    # only the events after the cursor are delivered
    assert ids and all(i > resume_at for i in ids)
    assert payloads[-1]["type"] == "done"
    # event AFTER resume_at is tool httpx then done (no re-delivery of stage/subfinder)
    assert [p["type"] for p in payloads] == ["tool", "done"]


# ---------------------------------------------------------------------------
# resume mid-scan: events that arrive after reconnect are still streamed
# ---------------------------------------------------------------------------
def test_no_cursor_replays_full_ledger_then_lives(client, auth_headers, session):
    import threading
    import time

    owner = _owner(session)
    project = Project(name="p108live", user_id=owner.id, scope_json=["live.example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="live.example.com",
                status="Running", stage="HTTP_SCAN")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    session.add(ScanEvent(scan_id=scan.id, event_type="stage",
                          data={"stage": "HTTP_SCAN", "status": "started"}, seq=1))
    session.commit()
    scan_id = scan.id

    def _finish():
        time.sleep(0.6)
        s = SessionLocal()
        try:
            s.add(ScanEvent(scan_id=scan_id, event_type="done",
                            data={"state": "COMPLETED"}, seq=2))
            s.commit()
        finally:
            s.close()

    t = threading.Thread(target=_finish, daemon=True)
    t.start()
    with client.stream("GET", f"/scans/{scan_id}/events", headers=auth_headers,
                       ) as stream:
        # cursorless request replays the existing ledger stage row, then keeps
        # living until the threaded pipeline terminalizes the scan.
        lines = []
        for line in stream.iter_lines():
            lines.append(line)
            if any("data: " in s and '"type": "done"' in s for s in lines):
                break
    t.join(timeout=5)

    payloads = _read_sse_payloads(lines)
    assert payloads and payloads[0]["type"] == "stage"
    assert payloads[-1]["type"] == "done"
    # the ledger rows that arrived after reconnect are still streamed
    assert [p["type"] for p in payloads] == ["stage", "done"]


# ---------------------------------------------------------------------------
# legacy/backfilled scan (no ScanEvent rows) keeps the diff-based wire
# ---------------------------------------------------------------------------
def test_legacy_terminal_scan_still_emits_done(client, auth_headers, session):
    from database.models import ToolResult

    user = session.query(User).filter(User.email == "owner@test.local").first()
    project = Project(name="legacy", user_id=user.id, scope_json=["legacy.example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="legacy.example.com", status="Completed",
                stage="COMPLETED", coverage=100.0, security_score=70.0)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    session.add(ToolResult(scan_id=scan.id, tool_name="nmap", status="Completed", raw_output="x"))
    session.commit()

    assert session.query(ScanEvent).filter(ScanEvent.scan_id == scan.id).first() is None

    with client.stream("GET", f"/scans/{scan.id}/events", headers=auth_headers) as stream:
        lines = _sse_lines(stream)
    payloads = _read_sse_payloads(lines)
    types = [p["type"] for p in payloads]
    assert types[-1] == "done"
    assert payloads[-1]["status"] == "Completed"
    assert "tool" in types
    tools = {p.get("tool") for p in payloads if p["type"] == "tool"}
    assert "nmap" in tools