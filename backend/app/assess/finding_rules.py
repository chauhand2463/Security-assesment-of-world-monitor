"""Findings engine -- deterministic security rules over persisted observations.

Phase 3 hard rule: a finding MUST be derived from at least one persisted
``Observation`` row.  Rules below never invent a vulnerability; each candidate
carries ``observation_ids`` and a human-readable ``evidence`` trail so the chain
finding -> evidence -> observation -> tool -> scan -> authorized target is fully
traceable.  With zero observations the engine produces zero findings.
"""
import datetime
from typing import Optional

# Severity -> score deduction for the deterministic security rating (documented
# policy; a scan with no evidence-backed findings keeps a score of 100).
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}
MIN_SCORE = 10

# Triage states that no longer count against the score.
RESOLVED_STATES = ("FALSE_POSITIVE", "DUPLICATE", "RESOLVED")


def severity_weight(severity: str) -> int:
    return SEVERITY_WEIGHTS.get((severity or "").strip().lower(), 0)


# ---------------------------------------------------------------------------
# Candidate builders (pure functions over observation dicts)
# ---------------------------------------------------------------------------
_MISSING_HEADER_META = {
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy header",
        "description": (
            "The web server responded without a Content-Security-Policy header, "
            "removing a primary browser-side control against XSS and injection "
            "of untrusted content."
        ),
        "remediation": (
            "Add a Content-Security-Policy response header (e.g. "
            "default-src 'self'); apply it via server middleware or reverse proxy."
        ),
    },
    "Strict-Transport-Security": {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "description": (
            "An HTTPS response was served without Strict-Transport-Security, so "
            "browsers are not forced to upgrade connections to TLS."
        ),
        "remediation": (
            "Serve Strict-Transport-Security on all HTTPS responses, preloaded "
            "where the domain is HSTS-preload eligible."
        ),
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options header",
        "description": (
            "The response did not set X-Content-Type-Options: nosniff, leaving "
            "browsers free to MIME-sniff responses, which can enable "
            "cross-origin content injection."
        ),
        "remediation": (
            "Add X-Content-Type-Options: nosniff to all responses."
        ),
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options header",
        "description": (
            "The response did not set X-Frame-Options (or a CSP frame-ancestors "
            "equivalent), so the page may be embedded in third-party frames "
            "(clickjacking)."
        ),
        "remediation": (
            "Deny framing via X-Frame-Options: DENY or a CSP frame-ancestors directive."
        ),
    },
}


def _missing_headers_candidate(obs: dict, header: str) -> Optional[dict]:
    url = obs.get("subject", "")
    headers_ok = (
        (obs.get("data") or {}).get("has_csp"),
        (obs.get("data") or {}).get("has_hsts"),
        (obs.get("data") or {}).get("has_xcto"),
        (obs.get("data") or {}).get("has_xframe"),
    )
    present = {
        "Content-Security-Policy": bool(headers_ok[0]),
        "Strict-Transport-Security": bool(headers_ok[1]),
        "X-Content-Type-Options": bool(headers_ok[2]),
        "X-Frame-Options": bool(headers_ok[3]),
    }
    if present[header]:
        return None
    # HSTS is only meaningful over HTTPS.
    if header == "Strict-Transport-Security" and (obs.get("data") or {}).get("scheme") != "https":
        return None
    meta = _MISSING_HEADER_META[header]
    return {
        "rule_id": "missing-security-header",
        "severity": "Low",
        "cvss": 3.1,
        "owasp": "A05:2021-Security Misconfiguration",
        "cwe": "CWE-693",
        "cve": None,
        "confidence": "intermediate",
        "title": meta["title"],
        "description": meta["description"],
        "remediation": meta["remediation"],
        "target": url,
        "proof": obs.get("raw", ""),
        "observation_ids": [obs.get("id")],
        "dedup_key": f"missing-security-header|{url}|{header}",
    }


def _server_version_candidate(obs: dict) -> Optional[dict]:
    data = obs.get("data") or {}
    hint = data.get("version_hint")
    if not hint:
        return None
    url = obs.get("subject", "")
    return {
        "rule_id": "server-version-banner",
        "severity": "Info",
        "cvss": 0.0,
        "owasp": "A05:2021-Security Misconfiguration",
        "cwe": "CWE-200",
        "cve": None,
        "confidence": "confirmed",
        "title": "Server software version disclosed in response banner",
        "description": (
            f"The server banner disclosed the software version ({hint}), which "
            "reduces attacker effort for fingerprinting and known-CVE targeting."
        ),
        "remediation": "Redact version details from Server/X-Powered-By headers.",
        "target": url,
        "proof": obs.get("raw", ""),
        "observation_ids": [obs.get("id")],
        "dedup_key": f"server-version-banner|{url}|{data.get('server') or hint}",
    }


def _jquery_candidate(obs: dict) -> Optional[dict]:
    data = obs.get("data") or {}
    if data.get("match") != "jquery_version":
        return None
    version = str(data.get("version") or "")
    try:
        parts = [int(p) for p in version.split(".")]
        parts += [0] * (3 - len(parts))
        ver = tuple(parts[:3])
    except ValueError:
        return None
    if ver >= (3, 7, 0):
        return None
    url = obs.get("subject", "")
    return {
        "rule_id": "outdated-jquery",
        "severity": "Medium",
        "cvss": 6.1,
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-79",
        "cve": "CVE-2015-9251",
        "confidence": "confirmed",
        "title": f"Outdated jQuery {version} with known vulnerabilities",
        "description": (
            f"Page content references jQuery {version}. Versions below 3.7.0 are "
            "affected by publicly documented cross-site scripting and prototype-"
            "pollution issues (e.g. CVE-2015-9251, CVE-2019-11358, CVE-2020-11022)."
        ),
        "remediation": "Upgrade jQuery to the latest supported 3.x release (>= 3.7.0).",
        "target": url,
        "proof": obs.get("raw", ""),
        "observation_ids": [obs.get("id")],
        "dedup_key": f"outdated-jquery|{url}|{version}",
    }


def _nuclei_candidate(obs: dict) -> Optional[dict]:
    data = obs.get("data") or {}
    title = data.get("title") or "Nuclei-reported finding"
    severity = (data.get("severity") or "info").capitalize()
    if severity.lower() not in SEVERITY_WEIGHTS:
        severity = "Info"
    return {
        "rule_id": "nuclei-reported-finding",
        "severity": severity,
        "cvss": None,
        "owasp": data.get("owasp"),
        "cwe": data.get("cwe"),
        "cve": data.get("cve"),
        "confidence": "confirmed",
        "title": title,
        "description": data.get("description") or "Nuclei engine reported a finding.",
        "remediation": data.get("remediation") or "Apply the relevant patch or fix.",
        "target": data.get("matched_at") or obs.get("subject", ""),
        "proof": obs.get("raw", ""),
        "observation_ids": [obs.get("id")],
        "dedup_key": f"nuclei-template|{data.get('template_id') or ''}|{data.get('matched_at') or ''}",
    }


def evaluate_observations(observations: list[dict],
                          config: Optional[dict] = None) -> list[dict]:
    """Run every enabled rule over the given observation dicts.

    Pure and deterministic.  Phase 10.5: the applied rule set comes from the
    detection registry honoured by ``config["detection_rules"]`` per-rule gates;
    when no gates exist every registered rule runs, exactly as before.
    """
    from app.assess import detection_registry as dr

    registry = dr.default_registry()
    enabled = registry.enabled(config)
    candidates: list[dict] = []
    for obs in observations:
        for rule in enabled:
            for candidate in rule.produce(obs):
                candidates.append(candidate)
    return candidates


def deduplicate(candidates: list[dict], existing_keys: set[str]) -> list[dict]:
    """Suppress candidates whose dedup identity already exists as an open finding."""
    seen: set[str] = set()
    kept = []
    for candidate in candidates:
        key = candidate.get("dedup_key") or ""
        if not key or key in seen or key in existing_keys:
            continue
        seen.add(key)
        kept.append(candidate)
    return kept


def compute_score(findings: list[dict]) -> int:
    """Deterministic rating: start at 100, deduct per open finding severity.

    Triage states that mark a finding as not applicable (FALSE_POSITIVE,
    DUPLICATE, RESOLVED) no longer affect the score.  A scan with no open
    findings keeps 100.
    """
    score = 100
    for finding in findings:
        if (finding.get("state") or "NEW").upper() in RESOLVED_STATES:
            continue
        score -= severity_weight(finding.get("severity") or "")
    return max(score, MIN_SCORE)


def now_utc() -> datetime.datetime:
    return datetime.datetime.utcnow()