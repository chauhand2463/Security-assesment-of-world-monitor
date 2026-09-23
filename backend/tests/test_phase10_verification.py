"""Phase 10.6 — deterministic verification engine tests.

Closes gap G6: findings now carry a ``verification_state`` backed by real
``verifications`` rows produced by a re-check that runs over the SAME persisted
observations the finding was derived from (no new network request):

  * a finding whose candidate is reproduced by its rule over its own persisted
    observations is ``verified``,
  * a finding that no longer reproduces is ``failed``,
  * a finding with no supporting observation is ``not_applicable``,
  * only a verified state flips ``verification_state``; rows are append-only so
    the chain finding -> verification -> observation -> tool -> scan is
    auditable and replayable.
"""
import uuid

import pytest

from tests.conftest import add_scope
from app.assess import verification as verify
from app.assess.verification import (
    VERIFICATION_FAILED,
    VERIFICATION_NOT_APPLICABLE,
    VERIFICATION_UNVERIFIED,
    VERIFICATION_VERIFIED,
    recheck_finding,
    run_verification,
)
from database.connection import SessionLocal
from database.models import Project, Scan, User, Verification, Vulnerability


def _make_scan(session, target="example.com", config=None):
    owner = User(id=f"p106-{uuid.uuid4().hex[:8]}",
                 email=f"p106-{uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p106", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="",
                scan_config=config)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _add_http_observation(session, scan, oid, *, version_hint):
    from database.models import Observation

    row = Observation(
        scan_id=scan.id, tool_name="http_probe", kind="http_response",
        subject=f"https://{scan.target}/", raw_output="HTTP/1.1 200 OK",
        data_json={
            "has_csp": False, "has_hsts": False, "has_xcto": False,
            "has_xframe": False, "scheme": "https",
            "version_hint": version_hint,
        },
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.id


def _add_nuclei_observation(session, scan, oid):
    from database.models import Observation

    row = Observation(
        scan_id=scan.id, tool_name="nuclei", kind="nuclei_finding",
        subject=f"https://{scan.target}/", raw_output="[match] exposure/",
        data_json={"matched": True, "template": "exposure/"},
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.id


# ---------------------------------------------------------------------------
# engine re-check semantics
# ---------------------------------------------------------------------------
def test_reproduced_candidate_is_verified():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        oid = _add_http_observation(session, scan, 1, version_hint=None)
        from app.assess import finding_rules as fr

        candidates = fr.evaluate_observations([
            {"id": oid, "kind": "http_response", "subject": f"https://{scan.target}/",
             "data": {"has_csp": False, "has_hsts": False, "has_xcto": False,
                      "has_xframe": False, "scheme": "https"}}
        ])
        assert any(c["rule_id"] == "missing-security-header" for c in candidates)
        cand = next(c for c in candidates if c["rule_id"] == "missing-security-header")
        finding = Vulnerability(
            scan_id=scan.id, title=cand["title"], severity=cand["severity"],
            description=cand["description"], rule_id=cand["rule_id"],
            dedup_key=cand["dedup_key"],
            evidence_observation_ids=[oid], status="candidate",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        row = recheck_finding(session, finding)
        session.commit()
        assert row.status == VERIFICATION_VERIFIED
        assert finding.verification_state == VERIFICATION_VERIFIED
        assert row.observation_ids == [oid]
        assert row.method == verify.METHOD_DETERMINISTIC_RULE
        assert row.finding_id == finding.id
    finally:
        session.close()


def test_no_supporting_observation_is_not_applicable():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        finding = Vulnerability(
            scan_id=scan.id, title="orphan", severity="Info",
            description="no evidence", status="candidate",
            rule_id="server-version-banner",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        row = recheck_finding(session, finding)
        session.commit()
        assert row.status == VERIFICATION_NOT_APPLICABLE
        assert finding.verification_state == VERIFICATION_NOT_APPLICABLE
        assert row.observation_ids == []
    finally:
        session.close()


def test_candidate_not_reproduced_is_failed():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        oid = _add_http_observation(session, scan, 1, version_hint="nginx/1.18.0")
        # The observation DOES reproduce server-version-banner, so fabricate a
        # finding claiming a different rule that does not fire on it.
        finding = Vulnerability(
            scan_id=scan.id, title="outdated jquery (never seen)",
            severity="Medium", description="no such body_match",
            rule_id="outdated-jquery", dedup_key="outdated-jquery|x",
            evidence_observation_ids=[oid], status="candidate",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        row = recheck_finding(session, finding)
        session.commit()
        assert row.status == VERIFICATION_FAILED
        assert finding.verification_state == VERIFICATION_FAILED
    finally:
        session.close()


def test_unknown_rule_with_matching_identity_can_verify():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        oid = _add_nuclei_observation(session, scan, 1)
        from app.assess import finding_rules as fr

        candidates = fr.evaluate_observations([
            {"id": oid, "kind": "nuclei_finding", "subject": f"https://{scan.target}/",
             "data": {"matched": True, "template": "exposure/"}}
        ])
        cand = next(c for c in candidates if c["rule_id"] == "nuclei-reported-finding")
        finding = Vulnerability(
            scan_id=scan.id, title=cand["title"], severity=cand["severity"],
            description=cand["description"], rule_id="nuclei.engine.custom",
            dedup_key=cand["dedup_key"],
            evidence_observation_ids=[oid], status="candidate",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        row = recheck_finding(session, finding)
        session.commit()
        assert row.status == VERIFICATION_VERIFIED
    finally:
        session.close()


# ---------------------------------------------------------------------------
# scan-wide runner
# ---------------------------------------------------------------------------
def test_run_verification_tallies_all_findings_and_commits():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        oid = _add_http_observation(session, scan, 1, version_hint="apache/2.4.29")
        from app.assess import finding_rules as fr

        obs = {"id": oid, "kind": "http_response", "subject": f"https://{scan.target}/",
               "data": {"has_csp": False, "has_hsts": False, "has_xcto": False,
                        "has_xframe": False, "scheme": "https"}}
        candidates = fr.evaluate_observations([obs])
        verified_finding = Vulnerability(
            scan_id=scan.id, title=candidates[0]["title"], severity="Low",
            description="ok", rule_id="missing-security-header",
            dedup_key=candidates[0]["dedup_key"],
            evidence_observation_ids=[oid], status="candidate",
        )
        failed_finding = Vulnerability(
            scan_id=scan.id, title="nope", severity="Info", description="no",
            rule_id="server-version-banner", dedup_key="server-version-banner|y",
            evidence_observation_ids=[oid], status="candidate",
        )
        orphan = Vulnerability(
            scan_id=scan.id, title="orphan", severity="Info", description="no",
            status="candidate",
        )
        session.add(verified_finding)
        session.add(failed_finding)
        session.add(orphan)
        session.commit()
        for f in (verified_finding, failed_finding, orphan):
            session.refresh(f)

        tally = run_verification(session, scan)
        session.commit()
        assert tally["checked"] == 3
        assert tally["states"][VERIFICATION_VERIFIED] == 1
        assert tally["states"][VERIFICATION_FAILED] == 1
        assert tally["states"][VERIFICATION_NOT_APPLICABLE] == 1
        assert tally["registry"]
        rows = session.query(Verification).filter(Verification.scan_id == scan.id).all()
        assert len(rows) == 3
        # append-only: a second run adds more rows, never rewrites history
        run_verification(session, scan)
        session.commit()
        assert session.query(Verification).filter(Verification.scan_id == scan.id).count() == 6
    finally:
        session.close()


def test_unverified_is_the_default():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        f = Vulnerability(scan_id=scan.id, title="t", severity="Info", description="d")
        session.add(f)
        session.commit()
        assert f.verification_state == VERIFICATION_UNVERIFIED
    finally:
        session.close()


# ---------------------------------------------------------------------------
# pipeline integration (hermetic run produces verification trail)
# ---------------------------------------------------------------------------
def test_pipeline_scan_leaves_verification_rows_and_logs(session):
    from app.orchestration import pipeline
    from database.models import Verification, Vulnerability

    scan = _make_scan(session, config={"tools": {"nuclei": False}})
    oid = _add_http_observation(session, scan, 1, version_hint="nginx/1.18.0")
    session.refresh(scan)

    # drive the deterministic assessment + validation + verification path
    pipeline._run_deterministic_assessment(session, scan, scan.scan_config or {}, {})
    session.commit()
    pipeline._run_validation(session, scan, scan.scan_config or {})
    session.commit()

    assert session.query(Verification).filter(Verification.scan_id == scan.id).count() > 0
    findings = session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    assert findings, "the http observation must produce at least one finding"
    assert all(f.verification_state in (VERIFICATION_VERIFIED, VERIFICATION_FAILED,
                                        VERIFICATION_NOT_APPLICABLE)
               for f in findings)
    assert any(f.verification_state == VERIFICATION_VERIFIED for f in findings)
    assert "[Verification]" in (scan.logs or "")
    session.rollback()


# ---------------------------------------------------------------------------
# API: verification_state + verifications visible on finding detail
# ---------------------------------------------------------------------------
def test_finding_detail_exposes_verification_state(client, session):
    from tests.conftest import login_user, register_user
    from database.models import User

    email = f"p106-api-{uuid.uuid4().hex[:8]}@test.local"
    register_user(client, email)
    headers = login_user(client, email)
    owner = session.query(User).filter(User.email == email).first()

    project = Project(name="p106-api", user_id=owner.id, scope_json=["example.com"])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target="example.com", status="Completed", logs="",
                scan_config={"tools": {"nuclei": False}})
    session.add(scan)
    session.commit()
    session.refresh(scan)

    oid = _add_http_observation(session, scan, 1, version_hint="nginx/1.18.0")
    finding = Vulnerability(
        scan_id=scan.id, title="server banner", severity="Info",
        description="banner", rule_id="server-version-banner",
        dedup_key=f"server-version-banner|https://{scan.target}/|nginx/1.18.0",
        evidence_observation_ids=[oid], status="candidate",
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)

    from app.assess.verification import recheck_finding

    recheck_finding(session, finding)
    session.commit()

    resp = client.get(f"/findings/{finding.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["verification_state"] == VERIFICATION_VERIFIED
    assert data["verifications"]
    assert data["verifications"][0]["status"] == VERIFICATION_VERIFIED
    assert data["verifications"][0]["observation_ids"] == [oid]