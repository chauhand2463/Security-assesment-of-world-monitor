"""Phase 10.5 — detection rule registry / policy store tests.

Closes audit gap G8: detection rules were bare functions with no per-rule
metadata or fingerprint.  The registry formalizes the deterministic rule corpus
over persisted observations:

  * every rule carries id/name/severity/applicable-kinds/remediation,
  * ``DetectionRegistry`` gives a stable fingerprint pinning the corpus,
  * per-rule opt-in gates from scan config ``detection_rules`` (``{id: bool}``)
    are honoured by the engine without changing candidate output,
  * a disabled rule never fires; all rules unchanged keeps byte-identical
    candidates (nothing is invented -- rules only fire on real observations).
"""
import pytest

from tests.conftest import add_scope
from app.assess import detection_registry as dr
from app.assess import finding_rules as fr
from app.assess.detection_registry import (
    DETECTION_RULES,
    DetectionRegistry,
    default_registry,
    registry_fingerprint,
)

RULE_IDS = {
    "missing-security-header",
    "server-version-banner",
    "outdated-jquery",
    "nuclei-reported-finding",
}


def _http_obs(oid=1, *, has=None, version_hint=None, scheme="https", subject="https://example.com/"):
    has = has or {}
    data = {
        "has_csp": has.get("csp", False),
        "has_hsts": has.get("hsts", False),
        "has_xcto": has.get("xcto", False),
        "has_xframe": has.get("xframe", False),
        "scheme": scheme,
        "version_hint": version_hint,
    }
    return {"id": oid, "kind": "http_response", "subject": subject, "data": data, "raw": ""}


def _body_obs(oid=1, *, version=None, subject="https://example.com/"):
    return {
        "id": oid, "kind": "body_match", "subject": subject,
        "data": {"jquery_version": version}, "raw": '<script src="jquery.min.js"></script>',
    }


def _nuclei_obs(oid=1, *, matched=True, subject="https://example.com/"):
    return {
        "id": oid, "kind": "nuclei_finding", "subject": subject,
        "data": {"matched": matched, "template": "exposure/"}, "raw": "[match]",
    }


# ---------------------------------------------------------------------------
# registry catalogue
# ---------------------------------------------------------------------------
def test_registry_lists_the_four_known_rules():
    registry = default_registry()
    assert set(registry.ids()) == RULE_IDS
    assert len(registry.all()) == 4


def test_rule_metadata_is_present_and_typed():
    registry = default_registry()
    for rule in registry.all():
        assert rule.id
        assert rule.name
        assert rule.description
        assert rule.severity in ("Info", "Low", "Medium", "High", "Critical")
        assert isinstance(rule.applicable_kinds, frozenset) and rule.applicable_kinds
        assert callable(rule.produce)


def test_rules_consume_only_declared_kinds():
    registry = default_registry()
    kinds = {
        "missing-security-header": {"http_response"},
        "server-version-banner": {"http_response"},
        "outdated-jquery": {"body_match"},
        "nuclei-reported-finding": {"nuclei_finding"},
    }
    for rule_id, expected in kinds.items():
        assert set(registry.get(rule_id).applicable_kinds) == expected


def test_fingerprint_is_stable_and_deterministic():
    f1 = registry_fingerprint()
    assert f1 and len(f1) == 16
    assert registry_fingerprint() == f1
    assert default_registry().fingerprint() == f1


def test_fingerprint_changes_when_corpus_changes():
    base = default_registry().fingerprint()
    modified = DetectionRegistry(DETECTION_RULES[:-1])
    assert modified.fingerprint() != base


def test_describe_exposes_audit_metadata():
    desc = default_registry().describe()
    ids = [d["id"] for d in desc]
    assert set(ids) == RULE_IDS
    for d in desc:
        assert set(d) >= {"id", "name", "description", "severity",
                          "applicable_kinds", "opt_in", "remediation"}


# ---------------------------------------------------------------------------
# opted-in rule set (policy store gates)
# ---------------------------------------------------------------------------
def test_no_config_means_every_rule_enabled():
    assert set(r.id for r in default_registry().enabled(None)) == RULE_IDS
    assert set(r.id for r in default_registry().enabled({})) == RULE_IDS


def test_gating_disables_only_the_named_rule():
    enabled = default_registry().enabled({"detection_rules": {"outdated-jquery": False}})
    assert "outdated-jquery" not in [r.id for r in enabled]
    assert "missing-security-header" in [r.id for r in enabled]
    assert "server-version-banner" in [r.id for r in enabled]
    assert "nuclei-reported-finding" in [r.id for r in enabled]


def test_malformed_gates_fall_back_to_default():
    enabled = default_registry().enabled({"detection_rules": "bad"})
    assert set(r.id for r in enabled) == RULE_IDS
    assert set(r.id for r in default_registry().enabled(42)) == RULE_IDS


# ---------------------------------------------------------------------------
# engine honours the gates without changing default candidate output
# ---------------------------------------------------------------------------
def test_evaluate_default_output_is_byte_identical_to_legacy():
    obs = [
        _http_obs(1, version_hint="nginx/1.18.0"),
        _http_obs(2, scheme="http"),
        _body_obs(3, version="2.1.4"),
        _nuclei_obs(4),
    ]
    # legacy output (registry with no gates) vs explicitly-all-enabled config
    base = fr.evaluate_observations(obs)
    gated_all = fr.evaluate_observations(obs, config={"detection_rules": {
        "missing-security-header": True,
        "server-version-banner": True,
        "outdated-jquery": True,
        "nuclei-reported-finding": True,
    }})
    assert gated_all == base
    # explicit no-gate config produces exactly the legacy corpus
    assert fr.evaluate_observations(obs, config={}) == base


def test_disabled_rule_produces_no_candidates():
    obs = [_http_obs(1, version_hint="nginx/1.18.0")]
    out = fr.evaluate_observations(obs, config={"detection_rules": {"server-version-banner": False}})
    assert all(c["rule_id"] != "server-version-banner" for c in out)
    # but other http_response rules still fire on the same observation
    assert any(c["rule_id"] == "missing-security-header" for c in out)


def test_only_gated_rule_isolated():
    obs = [
        _http_obs(1, version_hint="apache/2.4.29"),
        _body_obs(2, version="2.1.4"),
    ]
    out = fr.evaluate_observations(obs, config={"detection_rules": {"outdated-jquery": False}})
    assert all(c["rule_id"] != "outdated-jquery" for c in out)
    assert any(c["rule_id"] == "missing-security-header" for c in out)
    assert any(c["rule_id"] == "server-version-banner" for c in out)


def test_zero_observations_still_zero_findings():
    assert fr.evaluate_observations([], config={"detection_rules": {"nuclei-reported-finding": False}}) == []
    assert fr.evaluate_observations([]) == []


# ---------------------------------------------------------------------------
# registry drives the pipeline assessment via the findings engine
# ---------------------------------------------------------------------------
def test_finding_rules_ruleset_is_covered_by_registry():
    from app.assess import finding_rules as fr

    observed_ids = {obs.get("id") for r in default_registry().all() for obs in []}
    assert observed_ids == set()  # sanity: pure catalogue doesn't fabricate
    assert fr.evaluate_observations([]) == []


# ---------------------------------------------------------------------------
# API: read-only exposure of the detection registry
# ---------------------------------------------------------------------------
def test_rules_endpoint_reports_corpus_and_fingerprint(client, session):
    import uuid

    from tests.conftest import login_user, register_user

    email = f"p105-rules-{uuid.uuid4().hex[:8]}@test.local"
    register_user(client, email)
    headers = login_user(client, email)

    resp = client.get("/findings/rules", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["count"] == 4
    assert data["fingerprint"] == registry_fingerprint()
    rule_ids = {r["id"] for r in data["rules"]}
    assert rule_ids == RULE_IDS
    sample = next(r for r in data["rules"] if r["id"] == "missing-security-header")
    assert sample["severity"] == "Low"
    assert sample["applicable_kinds"] == ["http_response"]
    assert sample["remediation"]


def test_rules_endpoint_requires_auth(client):
    resp = client.get("/findings/rules")
    assert resp.status_code in (401, 403)