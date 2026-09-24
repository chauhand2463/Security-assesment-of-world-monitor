# Phase 11 — Real-Time Assessment Intelligence & Complete Vulnerability Discovery Pipeline (Architecture)

**Date:** 2026-09-24

Phase 11 makes the scanner *surface-aware before it assesses*: it natively
discovers the real attack surface (endpoints, query parameters, entry files) of
an authorized target, persists those discoveries as attributed observations and
assets, and lets the deterministic assessment pipeline reason over them. The
governing principle throughout is **honesty**: the system only ever reasons
about URLs, parameters and facts it actually observed over the network; it
never invents surface, never converts a hypothesis into a finding, and refuses
out-of-scope content instead of probing it.

## 1. Components and their jobs

### 1.1 Discovery domain (`backend/app/discovery/`)

Pure, network-free logic lives here so it is trivially testable.

- `endpoints.py` — parsing + reduction:
  - Link extraction from HTML (`links_from_html`, HTMLParser over `href`,
    `src`, `<form action>`).
  - `parse_robots` (Disallow + Sitemap; Allow is intentionally ignored — it
    only becomes a real candidate if independently observed) and `parse_sitemap`
    (every `<loc>`).
  - Normalization helpers: `to_absolute`, `endpoint_key`, `without_query`,
    `query_parameters`, `classify_document`.
  - `discover_from_documents(documents, guard)` → `DiscoveryReport` with
    observed endpoints (deduplicated by absolute URL, no query), parameters
    (from query strings actually seen), and refused out-of-scope URLs.
  - Observation kinds: `endpoint_candidate`, `parameter_candidate`,
    `endpoint_out_of_scope`, and the summary `endpoint_discovery`.
- `runner.py` — the bounded native HTTP pass:
  - `build_scan_guard(db, scan)` — scope guard (scan target + project scope).
  - `run_endpoint_discovery(db, scan, config, state)`: fetches `robots.txt`,
    sitemap(s) and the root HTML page per in-scope base URL, reduces the real
    content into observation dicts, and **never raises** (worst case: one
    honest `error` summary observation).
  - Budgets: `HttpLimits` 16 requests/scan, 8 % s timeout, redirect limit 3,
    400 KB response cap, `_MAX_HOSTS` 2, `_MAX_SITEMAPS_PER_BASE` 2. TLS
    capture is off for the discovery pass. `SafeHttpClient` is looked up at
    **call time** so tests/operators can substitute an offline client through
    the normal `app.http.client` attribute.

### 1.2 Orchestration integration (`backend/app/orchestration/`)

- `stages.py` — `endpoint_discovery` is registered as the native builtin
  `HTTP_DISCOVERY` stage and is **on by default** in `DEFAULT_TOOLS`.
- `executions.py` — dispatch branch for `tool == "endpoint_discovery"` runs
  `_run_endpoint_discovery`: persists the returned observation rows (with
  `source` and `status` copied into the row), finishes the run, records a
  `ToolResult`, emits the tool event, and returns success. `_adapter_kind`
  reports it as a `native_probe`.
- `pipeline.py::_populate_asset_graph` — discovered `endpoint_candidate`
  observations become real `endpoint` assets on the attack-surface graph,
  sourced `endpoint_discovery`. Observations of kind `endpoint_out_of_scope`
  are **excluded**: a refused URL must never appear in the attack-surface as if
  it were probed.

### 1.3 Tool contract (`backend/app/tools/manifest.py`)

`endpoint_discovery` is declared in the manifest (native tool, category `http`,
capability `URL_DISCOVERY`), so the preflight/probe/health machinery and the
frontend inventory treat it uniformly; it matches any == "endpoint_discovery"
intent and is schedulable by the standard planner.

## 2. The discovery flow

```
planner ──► scan stage HTTP_DISCOVERY ──► execute_tool("endpoint_discovery")
        ──► build_scan_guard (scope check before any socket)
        ──► SafeHttpClient (16 req, 8s, 400KB, redirect≤3, capture_tls=False)
        ──► robots.txt / sitemap / root HTML  (200 + body only)
        ──► discover_from_documents (pure reduction, dedup by absolute URL)
        ──► endpoint_candidate / parameter_candidate / out-of-scope / summary
        ──► persisted Observation rows (source, status, tool provenance)
        ──► asset graph: endpoint_candidate → Asset(type=endpoint,
                                                   source=endpoint_discovery)
        ──► candidate endpoints/parameters available to the Phase 5 engine's
            _candidate_endpoints and to verification (hypotheses never findings)
```

An empty or 4xx corpus yields **zero candidates** plus an honest summary — the
engine never invents surface from a failed fetch.

## 3. Interaction with the Phase 10 verification boundary

The discovered surface is a set of *hypotheses about the target's surface*, not
security claims. The Phase 11 extension deliberately stops at the same
enforcement point Phase 10 introduced:

- Findings are created only from **persisted observations**
  (`app/assess/engine.py::_persist_findings`, rule engine over observation
  rows), and `verification_state` flips only after a recorded deterministic
  re-check (`app/assess/verification.py`, orchestrated by
  `pipeline.py::_run_verification`).
- `endpoint_candidate` / `parameter_candidate` observations never feed the
  finding rules directly; they feed the *surface model* (`_candidate_endpoints`,
  assets, coverage), which the assessment phase then re-checks with its own
  evidence. No candidate endpoint is ever reported as a vulnerability by
  virtue of existing.
- ML/LLM output remains advisory-only in this system; no generated hypothesis
  can become a finding without persisted observation evidence and verification.

## 4. Why it is safe by construction

| Concern | Mechanism |
| --- | --- |
| Unauthorized probing | Every URL passes `build_scan_guard` before a socket opens; observed out-of-scope URLs are refused, never probed |
| Surface fabrication | Candidates derive only from real 200 bodies (robots/sitemap/HTML); empty/failed fetches → zero candidates |
| Runaway cost | Shared 16-request budget, 8 s timeouts, 400 KB response cap, ≤2 hosts, ≤2 sitemaps/base |
| Fake assets | Asset graph is populated only from persisted observations; refused URLs are excluded |
| Findings from guesses | Surface rows are hypotheses; findings still require observation evidence + verification |
| Hangs/false success | Runner never raises; a failure is surfaced as an honest `error` observation / gap |