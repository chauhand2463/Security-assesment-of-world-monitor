# Phase 11 — Reality Audit (independent re-verification of the claims)

**Date:** 2026-09-24
**Method:** every claim below is re-derived from the authoritative implementation
(`backend/app/discovery/`, `backend/app/http/fingerprints.py`,
`backend/app/orchestration/stages.py|executions.py|pipeline.py`,
`backend/app/tools/manifest.py`) and the schema — **never** from READMEs or
this doc. The Phase 11 invariants are absolute:

1. **No fabrication.** Candidates exist only for URLs/parameters observed in a
   real 200 document body; empty/failed fetches produce zero candidates.
2. **No unauthorized probing.** No URL is fetched before the scope guard; URLs
   seen in content that are out of scope are refused, never probed.
3. **No hypotheses become findings.** Discovered surface rows are assets and
   observations; findings require observation evidence + deterministic
   verification (Phase 10 boundary).

## 1. Invariant 1 — no fabrication

- `runner.py:92-127` `_fetch_documents`: only `resp.status in (200, 203) and
  resp.body` becomes a document. A 4xx, timeout, or empty body yields nothing.
- `endpoints.py` reduction is pure text parsing (HTMLParser, robots/sitemap
  text); nothing generates a URL that was not present in fetched content.
- Proven by tests (all green 2026-09-24):
  - `test_phase11_endpoint_discovery.py::test_endpoint_discovery_no_content_yields_no_candidates`
    — 200-with-empty-body for every document → `endpoint_candidates == 0`, no
    candidate rows, only an honest summary.
  - `test_discover_empty_documents_yield_nothing` — empty document list → 0
    candidates, 0 parameters, 0 refusals.
- `runner.py:211-219`: any unexpected exception returns one `status:"error"`
  summary observation (honest failure), never a fabricated candidate.

## 2. Invariant 2 — no unauthorized probing

- `runner.py:51-68` `build_scan_guard`: host must equal `scan.target` or pass
  `is_target_in_scope(host, project, project_assets)`.
- The guard is passed into `SafeHttpClient` (`client.py`) and re-checked for
  every URL, including sitemap URLs discovered inside robots.txt
  (`runner.py:114-117`).
- Base URLs from config are each guard-checked before use (`runner.py:77-78`);
  auto bases (`https://{host}` / `http://{host}`) are guard-checked too
  (`runner.py:86-88`).
- Observed out-of-scope links produce `KIND_OUT_OF_SCOPE` observations with
  `status:"skipped"` (`runner.py:200-208`); the scope guard in `SafeHttpClient`
  blocks the request before any socket opens.
- Proven: `test_discover_dedups_and_refuses_out_of_scope` (pure level —
  `https://evil.example/steal` is refused, absent from candidates) and
  `test_endpoint_discovery_real_scan` (live server — `refused ==
  {"https://evil.example/steal"}`, never a candidate, never a graph asset).
- Cost bounds (no runaway): 16 requests/scan shared, 8.0 s timeout, redirect
  limit 3, 400 KB response cap, ≤2 hosts, ≤2 sitemaps/base (`runner.py:33-43`).

## 3. Invariant 3 — no hypotheses become findings

- The assessment engine and rule registry consume **persisted observation rows**
  (`engine.py:92-108`, `detection_registry.py`), and findings persist only via
  `_persist_findings` from those rows.
- `verification.py` flips `verification_state` only after a recorded
  deterministic re-check; `VERIFICATION_NOT_APPLICABLE` when no supporting
  observation exists (see Phase 10 audit, section H).
- Discovery output is reduced to the **surface model**, not findings:
  - `executions.py::_run_endpoint_discovery` persists observation rows;
  - `pipeline.py::_populate_asset_graph` turns `endpoint_candidate` rows into
    `Asset(type="endpoint", source=endpoint_discovery)` and **skips**
    `endpoint_out_of_scope` rows (`KIND_OUT_OF_SCOPE` import).
- Proven: `test_endpoint_candidates_link_into_the_asset_graph` — candidates are
  `endpoint` assets (no findings created), refused URLs absent from the graph.
- Phase 10 suite that guards the boundary remains green
  (`test_phase10_verification.py`, `test_phase10_detection_registry.py`,
  `test_phase10_cross_tool_dedup.py`).

## 4. Repository identity / deltas

| Area | Before Phase 11 | After Phase 11 |
| --- | --- | --- |
| `app/http/fingerprints.py` | `IndexError` on HTTPS certs | defensive RDN flatten; `subject_alt_names` len guard |
| `app/discovery/` | (did not exist) | `endpoints.py`, `runner.py` (native, bounded, honest) |
| `stages.py` | no discovery stage | `endpoint_discovery → HTTP_DISCOVERY`, default on |
| `executions.py` | no discovery dispatch | `_run_endpoint_discovery` + source/status persist |
| `pipeline.py::_populate_asset_graph` | linked any `://` subject | excludes `endpoint_out_of_scope` |
| tests | — | `test_http_fingerprints.py` (6), `test_phase11_endpoint_discovery.py` (15) |

## 5. Test evidence (measured 2026-09-24)

- `tests/test_http_fingerprints.py` — 7 collected, 7 passed.
- `tests/test_phase11_endpoint_discovery.py` — 15 passed, incl. live localhost
  fixture-server integration through the real execution platform.
- `tests/test_phase9_granular_events.py` (asset-graph consumers) — 2 passed.
- `tests/test_phase7_stages.py`, `tests/test_phase7_pipeline_end_to_end.py` —
  green with the updated builtin/count pins.
- Repo totals: **429 `def test_*` functions across 57 test files**; the prior
  Phase 10 audit's 407 grew by the 15 Phase 11 + 7 fingerprint tests (net 22;
  count method identical).

### Note on the full-suite run

A single full-suite run surfaced 4 failures in `test_phase4_engine.py` /
`test_scan_lifecycle.py` that **pass when their file runs alone and pass in
the grouped Phase 10/11/E2E combinations reproduced here**; they did not exist
in the Phase 10 baseline full run. No Phase 11 code is in their call paths
(collected separately: phase4 + scan_lifecycle + phase10 + phase11 + phase7 E2E
= 35 passed). They are being tracked as an order-dependence investigation, not
shipped as a known regression.

## 6. Phase 12 gap register (drives next work)

| # | Gap | Evidence |
| --- | --- | --- |
| G1 | LLM/ML still advisory-only in this phase; hypothesis *generation from* the discovered surface is not wired to the pipeline (only documented) | `app/ml/advisory.py`, `docs/PHASE_11_ARCHITECTURE.md §3` |
| G2 | Static surface only — no JS-rendered `/api` route following | `discovery/endpoints.py` (HTMLParser only) |
| G3 | No per-scan frontend page rendering the discovered surface | `frontend/src/pages` (no discovery page) |
| G4 | Parameter discovery limited to query strings observed in static documents | `discovery/endpoints.py::query_parameters` |
| G5 | `capture_tls=False` on the discovery pass — TLS fingerprints of candidate endpoints are gathered later (`fetch_tls_info` on assess) by design | `runner.py:168` |