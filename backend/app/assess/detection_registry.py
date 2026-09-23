"""Detection rule registry (Phase 10.5).

Formalizes the deterministic findings engine over persisted observations as an
explicit, auditable catalogue -- closing the Phase 10 gap where rules were bare
functions with no per-rule metadata or fingerprint:

  * every rule is a ``DetectionRule`` record with id, name, description,
    severity, the observation kinds it consumes, a stable fingerprint share and
    an operator gate,
  * ``DetectionRegistry`` exposes lookup, description and a stable fingerprint
    pinning the exact rule corpus a scan's findings were derived from,
  * per-rule opt-in gates come from scan config ``detection_rules``
    (``{rule_id: bool}``); a rule explicitly disabled by the operator is not
    applied -- the finding trail is honest and reproducible.

Critically, this refactor is metadata-only: candidate output is byte-identical
to the previous function dispatch, so existing finding behaviour is preserved.
Nothing is invented -- rules still only fire on real persisted observations.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# rule record
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DetectionRule:
    id: str
    name: str
    description: str
    severity: str
    applicable_kinds: frozenset[str]
    # ``produce(observation) -> list[candidate dict]``; empty when the rule
    # does not fire on this observation.  Kept pure and deterministic.
    produce: Callable[[dict], list[dict]] = field(repr=False, compare=False)
    # A rule is on by default; the operator may gate it off per scan.  Default
    # True keeps every existing scan behaving identically until explicitly
    # configured otherwise.
    opt_in: bool = False
    # Human remediation hint consumed by the report/renderer.
    remediation: str = ""
    # Reference to the detection engine docs (epics across which the rule was
    # validated).  Not used in finding identity.
    epics: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# candidate producers (thin adapters over the existing finding_rules dispatch)
# ---------------------------------------------------------------------------
def _missing_headers_produce(obs: dict) -> list[dict]:
    from app.assess import finding_rules as fr

    if (obs.get("kind") or "").strip() != "http_response":
        return []
    out = []
    for header in fr._MISSING_HEADER_META:
        candidate = fr._missing_headers_candidate(obs, header)
        if candidate is not None:
            out.append(candidate)
    return out


def _server_banner_produce(obs: dict) -> list[dict]:
    from app.assess import finding_rules as fr

    if (obs.get("kind") or "").strip() != "http_response":
        return []
    candidate = fr._server_version_candidate(obs)
    return [candidate] if candidate is not None else []


def _jquery_produce(obs: dict) -> list[dict]:
    from app.assess import finding_rules as fr

    if (obs.get("kind") or "").strip() != "body_match":
        return []
    candidate = fr._jquery_candidate(obs)
    return [candidate] if candidate is not None else []


def _nuclei_produce(obs: dict) -> list[dict]:
    from app.assess import finding_rules as fr

    if (obs.get("kind") or "").strip() != "nuclei_finding":
        return []
    candidate = fr._nuclei_candidate(obs)
    return [candidate] if candidate is not None else []


# ---------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------
_RULES = (
    DetectionRule(
        id="missing-security-header",
        name="Missing security response header",
        description=("An HTTP response lacked a security header (CSP, HSTS, "
                     "nosniff or frame-ancestors), weakening browser-side "
                     "controls."),
        severity="Low",
        applicable_kinds=frozenset({"http_response"}),
        produce=_missing_headers_produce,
        opt_in=False,
        remediation="Add the missing security header server-side.",
        epics=frozenset({"epic5"}),
    ),
    DetectionRule(
        id="server-version-banner",
        name="Server software version disclosure",
        description=("The response banner disclosed the exact server software "
                     "version, easing fingerprinting for known-CVE targeting."),
        severity="Info",
        applicable_kinds=frozenset({"http_response"}),
        produce=_server_banner_produce,
        opt_in=False,
        remediation="Redact version details from Server headers.",
        epics=frozenset({"epic5"}),
    ),
    DetectionRule(
        id="outdated-jquery",
        name="Outdated jQuery with known vulnerabilities",
        description=("Page content references a jQuery release older than the "
                     "patched line, which is affected by documented "
                     "cross-site-scripting and prototype-pollution CVEs."),
        severity="Medium",
        applicable_kinds=frozenset({"body_match"}),
        produce=_jquery_produce,
        opt_in=False,
        remediation="Upgrade jQuery to >= 3.7.0.",
        epics=frozenset({"epic5"}),
    ),
    DetectionRule(
        id="nuclei-reported-finding",
        name="Nuclei engine reported finding",
        description=("The external nuclei engine reported a real match which "
                     "was normalized into a nuclei_finding observation."),
        severity="Info",
        applicable_kinds=frozenset({"nuclei_finding"}),
        produce=_nuclei_produce,
        opt_in=False,
        remediation="Apply the fix recommended for the matched template.",
        epics=frozenset({"epic3"}),
    ),
)

_RULES_BY_ID = {rule.id: rule for rule in _RULES}


class DetectionRegistry:
    """Explicit, ordered catalogue of detection rules (Phase 10.5)."""

    def __init__(self, rules=None) -> None:
        self._rules = list(rules if rules is not None else _RULES)
        self._by_id = {rule.id: rule for rule in self._rules}

    # -- access --------------------------------------------------------------
    def all(self) -> list[DetectionRule]:
        return list(self._rules)

    def get(self, rule_id: str) -> Optional[DetectionRule]:
        return self._by_id.get(rule_id)

    def ids(self) -> list[str]:
        return [rule.id for rule in self._rules]

    def by_kind(self, kind: str) -> list[DetectionRule]:
        return [r for r in self._rules if kind in r.applicable_kinds]

    def enabled(self, config: dict | None = None) -> list[DetectionRule]:
        """Rules the operator did not disable for this scan (deterministic).

        Gates come from ``config["detection_rules"]`` as ``{rule_id: bool}``.
        An absent rule id means "enabled by default" (backward compatible).
        """
        gates = {}
        raw = (config or {}).get("detection_rules") if isinstance(config, dict) else None
        if isinstance(raw, dict):
            gates = {str(k): bool(v) for k, v in raw.items()}
        return [r for r in self._rules if gates.get(r.id, True)]

    # -- audit ---------------------------------------------------------------
    def fingerprint(self) -> str:
        """Stable 16-hex digest pinning the rule corpus (id + metadata)."""
        digest = hashlib.sha256()
        for rule in self._rules:
            digest.update(f"{rule.id}\x00{rule.severity}\x00".encode("utf-8"))
            digest.update("".join(sorted(rule.applicable_kinds)).encode("utf-8"))
            digest.update(b"\x00")
        return digest.hexdigest()[:16]

    def describe(self) -> list[dict]:
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "applicable_kinds": sorted(rule.applicable_kinds),
                "opt_in": bool(rule.opt_in),
                "remediation": rule.remediation,
            }
            for rule in self._rules
        ]


def default_registry() -> DetectionRegistry:
    return DetectionRegistry(_RULES)


def registry_fingerprint() -> str:
    """Module-level convenience: the corpus fingerprint used by assessments."""
    return default_registry().fingerprint()


def _registered() -> dict[str, DetectionRule]:
    return dict(_RULES_BY_ID)


__all__ = [
    "DetectionRule", "DetectionRegistry", "DETECTION_RULES",
    "default_registry", "registry_fingerprint",
]

DETECTION_RULES = _RULES