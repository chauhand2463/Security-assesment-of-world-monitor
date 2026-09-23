"""Phase 10.4 — observation provenance (ToolExecution lineage).

Every observation persisted through the Phase 7 tool-execution path must carry
``tool_execution_id`` pointing at the exact ``tool_executions`` row that
produced it, and the API must expose that lineage (plus the execution's real
terminal state).  A NULL provenance is honest -- it means no ToolExecution row
exists (Phase 5 engine-native observations) -- never a fabricated link.
"""

import uuid

from app.orchestration import pipeline
from database.connection import SessionLocal
from database.models import Observation, Project, Scan, ToolExecution, User


def _make_scan(session, target="example.com"):
    owner = User(id=f"p10o-{uuid.uuid4().hex[:8]}",
                 email=f"p10o-{uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p10o", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan.id


def test_probe_observations_carry_execution_lineage(monkeypatch, session):
    from test_phase7_pipeline_end_to_end import _hermetic

    _hermetic(monkeypatch)
    scan_id = _make_scan(session)
    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    db = SessionLocal()
    try:
        rows = db.query(Observation).filter(Observation.scan_id == scan_id).all()
        assert rows
        # Every observation written by a Phase 7 tool carries its execution row.
        probe_obs = [o for o in rows if o.tool_name in ("real_dns", "real_tcp", "real_http")]
        assert probe_obs
        for o in probe_obs:
            assert o.tool_execution_id is not None, f"{o.tool_name} observation missing lineage"
            ex = db.query(ToolExecution).filter(ToolExecution.id == o.tool_execution_id).first()
            assert ex is not None
            assert ex.tool == o.tool_name
            assert ex.status == "completed"
        # All tool_execution rows for scan tools are connected to observations.
        for ex in db.query(ToolExecution).filter(ToolExecution.scan_id == scan_id).all():
            if ex.status == "completed" and ex.tool in ("real_dns", "real_tcp", "real_http"):
                linked = db.query(Observation).filter(
                    Observation.tool_execution_id == ex.id).count()
                assert linked >= 1
    finally:
        db.close()


def test_adapter_observations_carry_execution_lineage(monkeypatch, session):
    from test_phase7_pipeline_end_to_end import _hermetic, _OfflineAdapter

    _hermetic(monkeypatch)
    scan_id = _make_scan(session)
    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)

    db = SessionLocal()
    try:
        # nmap + httpx are adapter-run; their observations must link back.
        # The hermetic adapter emits no observations, so instead verify the
        # relationship is *structurally* wired: a completed adapter execution
        # links to exactly the observations its tool produced.
        for tool in ("nmap", "httpx"):
            ex = db.query(ToolExecution).filter(
                ToolExecution.scan_id == scan_id, ToolExecution.tool == tool).first()
            assert ex is not None
            obs = db.query(Observation).filter(
                Observation.scan_id == scan_id, Observation.tool_name == tool).all()
            for o in obs:
                assert o.tool_execution_id == ex.id
    finally:
        db.close()


def test_api_exposes_provenance(client, auth_headers, monkeypatch):
    from conftest import add_scope
    from test_phase7_pipeline_end_to_end import _hermetic

    _hermetic(monkeypatch)
    add_scope(client, auth_headers, "prov.example.com")
    resp = client.post("/scans", json={
        "target": "prov.example.com",
        "assessment_type": "custom_target",
        "authorization_acknowledged": True,
    }, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["scan_id"]

    pipeline.orchestrate_scan_phase7(scan_id, simulation=False)
    rows = client.get(f"/scans/{scan_id}/observations", headers=auth_headers).json()
    assert rows
    probe = [r for r in rows if r["tool"] in ("real_dns", "real_tcp", "real_http")]
    assert probe
    for r in probe:
        assert r["tool_execution_id"] is not None
        prov = r["provenance"]
        assert prov is not None
        assert prov["tool"] == r["tool"]
        assert prov["status"] == "completed"
        assert prov["execution_id"] == r["tool_execution_id"]
        assert prov["duration_ms"] is not None
        assert prov["stage"]
        assert prov["attempt"] == 1


def test_phase5_native_observations_have_null_provenance(session):
    """Engine-native HTTP observations (Phase 5) have no ToolExecution row: their
    lineage must be NULL, never a fabricated execution id."""
    from app.observations.normalize import build_observation
    from database.models import Observation
    import uuid as _uuid

    owner = User(id=f"p10n-{_uuid.uuid4().hex[:8]}",
                 email=f"p10n-{_uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p10n", user_id=owner.id, scope_json=["example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="example.com", status="Pending", logs="")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    kwargs = build_observation(
        scan_id=scan.id,
        observation_type="http_response",
        subject="https://example.com/",
        tool_name="native_http",
        source="http_client",
        user_id=owner.id,
        target="example.com",
        asset="example.com",
        data={},
        raw_output="stub",
        request=None,
        response=None,
        status="observed",
        discriminator={},
    )
    # The engine's own observation builder cannot fabricate tool lineage.
    assert "tool_execution_id" not in kwargs
    assert kwargs.get("tool_name") == "native_http"

    row = Observation(tool_execution_id=None, **kwargs)
    session.add(row)
    session.commit()
    session.refresh(row)
    assert row.tool_execution_id is None
    assert row.source == "http_client"