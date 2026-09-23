"""Phase 10.7 — cross-tool finding deduplication tests.

Closes gap G7: external candidates previously used ``external:{tool}:…`` keys
while native findings used ``finding_fingerprint`` -- the SAME issue reported by
nuclei and by the native engine would NOT collide.  Now every finding derives
its identity from ONE fingerprint namespace (``finding_fingerprint``):

  * an external candidate whose fingerprint matches an existing finding does NOT
    duplicate it -- the real external observation is merged in as corroborating
    evidence (observation link + source tool) and the finding's status/history
    is preserved untouched,
  * a brand-new external issue still becomes a candidate with the shared
    fingerprint, never ``external:…``.
"""
import uuid

from tests.conftest import add_scope
from app.assess import finding_lifecycle as lifecycle
from app.observations.fingerprint import finding_fingerprint
from app.observations.types import OBS_VULNERABILITY
from database.connection import SessionLocal
from database.models import FindingObservationLink, Project, Scan, User, Vulnerability


def _make_scan(session, target="example.com"):
    owner = User(id=f"p107-{uuid.uuid4().hex[:8]}",
                 email=f"p107-{uuid.uuid4().hex[:8]}@test.local", role="user")
    session.add(owner)
    session.commit()
    project = Project(name="p107", user_id=owner.id, scope_json=[target])
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=target, status="Pending", logs="")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _add_vuln_observation(session, scan, *, tool, category, name, oid=None):
    from database.models import Observation

    row = Observation(
        scan_id=scan.id, tool_name=tool, kind="tool_output",
        observation_type=OBS_VULNERABILITY,
        subject=f"https://{scan.target}/app",
        raw_output=f"[match] {name}",
        data_json={"name": name, "template": f"{tool}/{name}", "severity": "High",
                   "category": category},
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.id


# ---------------------------------------------------------------------------
# one fingerprint namespace
# ---------------------------------------------------------------------------
def test_external_candidate_uses_fingerprint_namespace():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        oid = _add_vuln_observation(session, scan, tool="nuclei", category="ssl",
                                    name="Heartbleed-Signature")
        from app.assess import engine as engine_mod

        engine_mod._persist_external_candidates(session, scan)
        session.commit()

        rows = session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        assert len(rows) == 1
        f = rows[0]
        expected = finding_fingerprint("ssl", scan.target,
                                       "https://example.com/app", None)
        assert f.dedup_key == expected
        assert f.fingerprint == expected
        assert "external:" not in (f.dedup_key or "")
        assert f.status == lifecycle.STATUS_CANDIDATE
        assert "nuclei" in f.source_tool
    finally:
        session.close()


def test_same_issue_from_two_tools_collides():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        oid1 = _add_vuln_observation(session, scan, tool="nuclei", category="ssl",
                                     name="Heartbleed-Signature")
        _add_vuln_observation(session, scan, tool="testssl", category="ssl",
                              name="Heartbleed-Signature")
        from app.assess import engine as engine_mod

        engine_mod._persist_external_candidates(session, scan)
        session.commit()

        rows = session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        assert len(rows) == 1, "identical issue from two tools must collapse"
    finally:
        session.close()


# ---------------------------------------------------------------------------
# merge into an existing (native-confirmed) finding
# ---------------------------------------------------------------------------
def test_external_observation_merges_into_existing_finding():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        oid = _add_vuln_observation(session, scan, tool="nuclei", category="ssl",
                                    name="Heartbleed-Signature")
        fingerprint = finding_fingerprint("ssl", scan.target,
                                          "https://example.com/app", None)
        native = Vulnerability(
            scan_id=scan.id, title="TLS heartbeat leak", severity="High",
            description="native-confirmed", rule_id="tls",
            dedup_key=fingerprint, fingerprint=fingerprint,
            state="NEW", category="ssl", endpoint="https://example.com/app",
            source_tool="native_http", confidence="HIGH",
            status=lifecycle.STATUS_CONFIRMED,
        )
        session.add(native)
        session.commit()
        session.refresh(native)
        lifecycle.record_initial(session, native, reason="validated by tls")
        session.commit()
        history_before = len(native.status_history)

        from app.assess import engine as engine_mod

        engine_mod._persist_external_candidates(session, scan)
        session.commit()
        session.refresh(native)

        # exactly one finding, and it is the native one (status preserved)
        rows = session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        assert len(rows) == 1
        assert rows[0].id == native.id
        assert rows[0].status == lifecycle.STATUS_CONFIRMED
        # history untouched (no status transition happened)
        assert len(rows[0].status_history) == history_before
        # the external observation is attached as corroborating evidence
        assert oid in (rows[0].evidence_observation_ids or [])
        link = (
            session.query(FindingObservationLink)
            .filter(FindingObservationLink.finding_id == rows[0].id,
                    FindingObservationLink.observation_id == oid)
            .first()
        )
        assert link is not None
        assert "nuclei" in rows[0].source_tool
        # only one observation was created, but the fingerprint must still match
        assert rows[0].fingerprint == fingerprint
    finally:
        session.close()


def test_merge_never_creates_duplicate():
    session = SessionLocal()
    try:
        scan = _make_scan(session)
        _add_vuln_observation(session, scan, tool="nuclei", category="ssl",
                              name="Heartbleed-Signature")
        _add_vuln_observation(session, scan, tool="testssl", category="ssl",
                              name="Heartbleed-Signature")
        fingerprint = finding_fingerprint("ssl", scan.target,
                                          "https://example.com/app", None)
        native = Vulnerability(
            scan_id=scan.id, title="TLS heartbeat leak", severity="High",
            description="native", dedup_key=fingerprint, fingerprint=fingerprint,
            state="NEW", category="ssl", status=lifecycle.STATUS_CONFIRMED,
        )
        session.add(native)
        session.commit()

        from app.assess import engine as engine_mod

        engine_mod._persist_external_candidates(session, scan)
        session.commit()

        rows = session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        assert len(rows) == 1, "multiple matching obs must still collapse to one finding"
    finally:
        session.close()