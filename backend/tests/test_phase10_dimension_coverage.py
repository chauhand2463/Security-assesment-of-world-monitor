"""Phase 10.11 -- dimension coverage (G9).

Task coverage only measures completed/total planned tasks.  These tests prove
that the API surfaces *dimension coverage* derived from real persisted rows:
how many distinct hosts / ports / URLs the scan actually observed, and which
tools captured each dimension.  No dimension value is guessed: everything is
read back from ``observations`` for the scan.
"""
from __future__ import annotations

from database.models import Observation, Scan


def _project(session):
    from database.models import Project

    existing = session.query(Project).first()
    if existing is not None:
        return existing.id
    project = Project(name="dims-unit", user_id="unit-user", scope_json=["example.com"])
    session.add(project)
    session.commit()
    return project.id


# ---------------------------------------------------------------------------
# unit: dimension aggregation from real observations
# ---------------------------------------------------------------------------
def test_dimension_coverage_aggregates_real_rows(session):
    from app.orchestration.dimensions import dimension_coverage

    scan = Scan(project_id=_project(session), target="example.com", status="Completed", stage="completed",
                coverage=100.0, progress={"completed_tasks": 5, "total_tasks": 5})
    session.add(scan)
    session.flush()

    session.add(Observation(scan_id=scan.id, tool_name="nmap", kind="port",
                            subject="example.com",
                            data_json={"host": "example.com", "port": 443}))
    session.add(Observation(scan_id=scan.id, tool_name="nmap", kind="port",
                            subject="example.com",
                            data_json={"host": "example.com", "port": 80}))
    session.add(Observation(scan_id=scan.id, tool_name="httpx", kind="http",
                            subject="https://example.com/login",
                            data_json={"url": "https://example.com/login"}))
    session.add(Observation(scan_id=scan.id, tool_name="subfinder", kind="host",
                            subject="api.example.com"))
    session.commit()

    dims = dimension_coverage(session, scan.id, scan.target)
    assert dims["hosts"]["observed"] == 2
    assert dims["hosts"]["distinct"] == ["api.example.com", "example.com"]
    assert dims["ports"]["observed"] == 2
    assert dims["ports"]["distinct"] == [80, 443]
    assert dims["urls"]["observed"] == 1
    assert dims["urls"]["distinct"] == ["https://example.com/login"]
    assert dims["scan_target_observed"] == "example.com"
    assert "nmap" in dims["ports"]["tools"]
    assert "httpx" in dims["urls"]["tools"]
    by_tool = dims["by_tool"]
    assert by_tool["nmap"]["ports"] == 2
    assert by_tool["httpx"]["urls"] == 1
    assert by_tool["subfinder"]["hosts"] == 1


def test_dimension_coverage_empty_scan(session):
    from app.orchestration.dimensions import dimension_coverage

    scan = Scan(project_id=_project(session), target="example.com", status="Completed")
    session.add(scan)
    session.commit()

    dims = dimension_coverage(session, scan.id, scan.target)
    assert dims["hosts"]["observed"] == 0
    assert dims["ports"]["observed"] == 0
    assert dims["urls"]["observed"] == 0
    assert dims["scan_target_observed"] is None
    assert dims["by_tool"] == {}


def test_dimension_no_guess_for_unstructured_rows(session):
    from app.orchestration.dimensions import dimension_coverage

    scan = Scan(project_id=_project(session), target="example.com")
    session.add(scan)
    session.flush()
    # an observation with no port/url-structured data counts for hosts only
    session.add(Observation(scan_id=scan.id, tool_name="dnsx", kind="dns",
                            subject="example.com", data_json={}))
    session.commit()
    dims = dimension_coverage(session, scan.id, scan.target)
    assert dims["hosts"]["observed"] == 1
    assert dims["ports"]["observed"] == 0
    assert dims["urls"]["observed"] == 0


# ---------------------------------------------------------------------------
# API: coverage endpoint + scan detail surface dimensions from real rows
# ---------------------------------------------------------------------------
def test_coverage_endpoint_exposes_dimensions(client, auth_headers, session):
    from app.agents.lifecycle import empty_progress
    from database.models import Project, User

    owner = session.query(User).filter(User.email == "owner@test.local").first()
    project = session.query(Project).filter(Project.user_id == owner.id).first()
    if project is None:
        project = Project(name="dims", user_id=owner.id, scope_json=["dims.example.com"])
        session.add(project)
        session.commit()
    scan = Scan(project_id=project.id, target="dims.example.com",
                status="Completed", stage="completed", coverage=95.0,
                progress={**empty_progress(), "total_tasks": 4, "completed_tasks": 4, "percent": 100.0})
    session.add(scan)
    session.flush()
    session.add(Observation(scan_id=scan.id, tool_name="nmap", kind="port",
                            subject="dims.example.com", data_json={"port": 22, "host": "dims.example.com"}))
    session.commit()
    scan_id = scan.id

    body = client.get(f"/scans/{scan_id}/coverage", headers=auth_headers).json()
    assert body["coverage"] == 95.0
    dims = body["dimensions"]
    assert dims["hosts"]["observed"] == 1
    assert dims["ports"]["distinct"] == [22]
    assert dims["scan_target_observed"].endswith("dims.example.com")

    detail = client.get(f"/scans/{scan_id}", headers=auth_headers).json()
    assert detail["dimensions"]["ports"]["observed"] == 1
    assert detail["dimensions"]["by_tool"]["nmap"]["observations"] >= 1


def test_dimension_target_observed_uses_scan_target_not_url(client, auth_headers, session):
    """An HTTP observation is attributed to its host, not a guessed URL host."""
    from database.models import Project, User

    owner = session.query(User).filter(User.email == "owner@test.local").first()
    project = Project(name="dims2", user_id=owner.id, scope_json=["dims2.example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="dims2.example.com", status="Completed")
    session.add(scan)
    session.flush()
    session.add(Observation(scan_id=scan.id, tool_name="httpx", kind="http",
                            subject="https://dims2.example.com/", data_json={}))
    session.commit()

    body = client.get(f"/scans/{scan.id}/coverage", headers=auth_headers).json()
    dims = body["dimensions"]
    assert dims["hosts"]["distinct"] == ["dims2.example.com"]
    assert dims["urls"]["distinct"] == ["https://dims2.example.com/"]
    assert dims["scan_target_observed"] == "dims2.example.com"