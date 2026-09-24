# Phase 11 — Real-Time Assessment Intelligence & Complete Vulnerability Discovery Pipeline (Implementation)

**Date:** 2026-09-24
**Scope:** the Phase 11 slices landed in this repository, with file:line
anchors for every behavioural claim. It reuses the Phase 10 platform (bounded
scheduler, tool execution ledger, verification engine) — it does not fork it.

## 0. N + 1 bug fix (the reason Phase 11 exists)

`POST /world-monitor/targets/{id}/discover` crashed with
`IndexError: tuple index out of range` at
`backend/app/http/fingerprints.py:75` whenever the target base URL was HTTPS
(`capture_tls=True`).

- Root cause: `ssl.SSLSocket.getpeercert()` returns `subject`/`issuer` as RDN
  *groups*; a single-attribute group is a 1-tuple, so `part[1]` in the old
  `_name_tuple` raised.
- Fix (`backend/app/http/fingerprints.py`):
  - `_name_tuple` reconstructed to flatten RDN groups defensively — both loops
    guarded; a malformed/empty group contributes nothing; a scalar is coerced
    to `str`; never raises.
  - `subject_alt_names` now skips any `entry` that is not a `(tuple, list)` of
    length ≥ 2.
- Regression tests: `backend/tests/test_http_fingerprints.py` (the 1-tuple RDN
  group that produced the real crash is the first test case).
- The whole flow (discover → `health.check_health` → `_build_response` →
  `fetch_tls_info`) now returns a 200 with honest TLS data.

## 1. Slice 1 — native endpoint discovery (IMPLEMENTED)

### New module: `backend/app/discovery/endpoints.py`

- Link reduction: `links_from_html` (HTMLParser; `href`, `src`, `<form
  action>`), `parse_robots` (Disallow + Sitemap, Allow ignored), `parse_sitemap`
  (all `<loc>`).
- Normalization: `to_absolute`, `endpoint_key` (scheme+host+path, trailing
  slash folded), `without_query`, `query_parameters` (real query strings only),
  `classify_document`.
- `discover_from_documents(documents, guard)` returns a `DiscoveryReport` of
  `endpoints` (deduped absolute URLs), `parameters` and `refused` (out-of-scope
  URLs observed in content). Only 200/203 responses with a body are documents.
- Kinds/sources: `endpoint_candidate` / `parameter_candidate` /
  `endpoint_out_of_scope` / `endpoint_discovery`; sources `robots`,
  `robots.sitemap`, `sitemap`, `html`.

### New module: `backend/app/discovery/runner.py`

- `build_scan_guard(db, scan)` — `(url) -> bool` over the scan target + project
  scope (`app.core.auth.is_target_in_scope`).
- `run_endpoint_discovery(db, scan, config, state)`:
  - Bases: explicit `endpoint_discovery.base_urls` (each scope-checked), else
    the scan's hosts (https then http, `_MAX_HOSTS`=2).
  - `_fetch_documents`: robots → sitemap(s) → root HTML per base, sharing one
    `SafeHttpClient` with limits `HttpLimits(max_requests_per_scan=16,
    request_timeout=8.0, redirect_limit=3, response_size_limit=400_000)` and
    `capture_tls=False`.
  - Output observations carry `source: native_discovery`, `status`, and honest
    `data`/`raw`. A summary observation records bases attempted, requests made,
    candidate counts, per-source tally and refusals.
  - `try/except` wrapper: the runner never raises — a failure yields one
    `status: "error"` summary observation.
  - `SafeHttpClient` imported **inside** `run_endpoint_discovery` (call-time
    lookup) so offline/patched clients take effect; an import-time binding made
    the hermetic E2E monkeypatch leak into later tests.

### Orchestration wiring

- `backend/app/orchestration/stages.py`:
  - `TOOL_TO_STAGE["endpoint_discovery"] = HTTP_DISCOVERY`.
  - `DEFAULT_TOOLS["endpoint_discovery"] = True` (default on, opt-out per scan).
- `backend/app/orchestration/executions.py`:
  - dispatch branch `if tool == "endpoint_discovery"` → `_run_endpoint_discovery`
    (persist observation rows, finish execution, save `ToolResult`, emit tool
    event, return `success`).
  - `_adapter_kind("endpoint_discovery")` → `"native_probe"`.
  - `_persist_observations` copies `o.get("source")` → `row.source` and
    `o.get("status")` → `row.status` for discovery-shaped rows.
- `backend/app/tools/manifest.py`: ScannerManifest entry (native, category
  `http`, capability `URL_DISCOVERY`, matches `endpoint_discovery` intent).

### Asset-graph persistence (Slice 2 anchor)

- `backend/app/orchestration/pipeline.py::_populate_asset_graph`:
  - `endpoint_candidate` observations (subject is an absolute URL) become
    `Asset(type="endpoint", source=endpoint_discovery)` under their host asset.
  - `endpoint_out_of_scope` observations are **skipped** (import
    `KIND_OUT_OF_SCOPE`) — a refused URL never enters the attack-surface.

## 2. Slice 2 — surface persistence & API (IMPLEMENTED via existing platform)

- Every candidate/parameter/refusal is a first-class `observations` row (kind,
  subject, `source`, `status`, `data_json`, `raw_output`, tool provenance via
  `tool_execution_id`), so the existing data plane exposes them:
  - `GET /scans/{id}/observations` (all kinds),
  - `GET /scans/{id}/assets` (the deduplicated attack-surface graph, built
    only from persisted observations),
  - SSE `observation.created` granular events.
- No new table was needed: candidates are observations, and their reduction to
  a graph is recomputed from rows by `_populate_asset_graph`. Parameters remain
  observations (a parameter is a fact about a URL, not a graph node).
- Frontend: the tool inventory automatically lists `endpoint_discovery`
  (manifest-driven); a dedicated per-scan view is a Phase 12 UI item, not a
  backend gap.

## 3. Slice 3 — hypothesis boundary & verification wiring (DOCUMENTED + enforced)

Phase 11 does not re-invent enforcement; it documents and pins the existing
boundary and layers surface hypothesis on its hypothesis side:

- Findings are produced **only** from persisted observations:
  `app/assess/engine.py::run_assessment` → `_persist_findings`; the rule engine
  (`app/assess/detection_registry.py`, `finding_rules.py`) consumes declared
  observation kinds only.
- `verification_state` flips only via recorded deterministic re-checks:
  `app/assess/verification.py::run_verification`, orchestrated at
  `pipeline.py::_run_verification` (`VERIFICATION_NOT_APPLICABLE` for findings
  with no supporting observation).
- ML/LLM output (`app/ml/advisory.py`) is advisory-only and never creates
  findings.
- Discovered endpoints/parameters are hypotheses about the surface; the
  assessment phase re-checks them with its own evidence (Surface model →
  `_candidate_endpoints` → deterministic findings). Existence alone never
  produces a finding.
- Test pinning the boundary: `test_endpoint_candidates_link_into_the_asset_graph`
  asserts candidates become **assets** (not findings) and refused URLs stay out
  of the graph.

## 4. Tests

- `backend/tests/test_http_fingerprints.py` — 7 regression tests for the TLS
  name/shape bug.
- `backend/tests/test_phase11_endpoint_discovery.py` — 15 tests:
  - pure parsing units (robots, sitemap, HTML links, query params, dedup,
    absolute-URL folding, out-of-scope refusal),
  - scope-guard units,
  - integration against a live localhost fixture server through
    `executions.execute_tool` (candidate/parameter/summary rows persist),
  - disabled-tool → skipped, empty-content → zero candidates,
  - asset-graph linkage + refusal exclusion, and
  - enabled-tool default check.
- `backend/tests/test_phase7_stages.py` — builtin set now includes
  `endpoint_discovery`.
- `backend/tests/test_phase7_pipeline_end_to_end.py` — pinned row/task counts
  updated (tool_discovery is now a default planned tool).

### Known non-goals (recorded honestly)

- No LLM-driven discovery loop yet (hypothesis *generation* is wired as
  documentation + boundary; the actual tooling calls are Phase 12).
- Discovery does not follow HTML `<script src>` data flows or JS-rendered
  routes; it observes the static surface served by the target.
- No new per-scan frontend page for the discovered surface in this slice.