# PHASE 12 — Surface Intelligence & Continuous Assessment (Implementation)

Status: implemented and tested (this phase completed).

## Scope

Phase 12 turns the *observed evidence chain* into an explicit, auditable attack
surface with a deterministic assessment program and a real scheduling loop.
Everything displayed and planned is derived **only** from persisted
`Observation` / `Asset` / `AssessmentTest` rows. Nothing is guessed.

## Slice 1 — Surface inventory, events, planner, API

### Discovery modules (read-only façades)

| Module | Responsibility |
| --- | --- |
| `app/discovery/context.py` | `scan_context(db, scan)` — hosts (schemes / explicit + default ports / kinds / first+last seen), observation-kind counts, sources, asset count, HTTP-subject count. |
| `app/discovery/inventory.py` | `endpoint_inventory` (dedupe by `endpoint_key`, query-stripped, `url`/`scheme`/`host`/`sources`/`kinds`/`observation_ids`/first+last seen, `parameter_count`, limit 500), `api_documents`, `script_assets`, `surface_coverage`, `surface_snapshot`. |
| `app/discovery/parameters.py` | `parameter_inventory` — parameter **names only**, `value_shape` (`present`/`empty`), `value_sensitive` hint, provenance. Values are never emitted. |
| `app/discovery/endpoints.py` | `endpoint_key`, `normalize_endpoint`, `without_query`, `query_parameters` — URL canonicalisation helpers. |
| `app/assess/surface_planner.py` | `plan_surface` — deterministic plan: for every registered test decide `planned` / `skipped` + human reason, with explicit endpoint / parameter scopes. `ENDPOINT_SCOPED_CATEGORIES` = headers, cors, cookies, methods, redirects, tls, disclosure; `PARAMETER_SCOPED_CATEGORIES` = xss, sqli, ssti, ssrf, idor, authorization, auth, jwt, oauth, graphql. |

### Discovery runner additions

`app/discovery/runner.py` now:
- records `script_asset` observations by parsing `<script src>` from served HTML (raw bytes only, in-memory; `urljoin` relative to the document URL),
- probes `../openapi.json`, `../openapi.yaml`, `./openapi.json`, `./openapi.yaml`, `../swagger.json` (`_MAX_OPENAPI_PER_BASE`), parsing JSON documents (no PyYAML — YAML is recorded `status: unsupported`), emitting `api_document` plus `api_endpoint_candidate` / `api_parameter_candidate` rows; stops per base after the first parsed document; honours an enlarged request budget (28 max per scan / per test).

### Events (SSE + persisted)

`app/orchestration/events.py` adds `endpoint.discovered`, `parameter.discovered`, `assessment.item` (+ emit helpers `emit_endpoint_discovered`, `emit_parameter_discovered`, `emit_assessment_item`). Emitters:
- `app/orchestration/executions.py::_persist_observations` emits endpoint/parameter events per persisted kind,
- `app/assess/engine.py::_persist_assessment_tests` populates `AssessmentTest.endpoint` (from produced observation subjects) and emits `assessment.item` after flush.

### API

`app/api/scans.py`:
- `GET /scans/{id}/surface` — full snapshot,
- `GET /scans/{id}/surface/endpoints` and `/surface/parameters`,
- `GET /scans/{id}/assessment-plan`,
- `GET /scans/{id}/timeline` — chronological surface-discovery stream (`ScanEvent` rows; note: the model exposes its payload on the `data` JSON column),
- `GET /scans/{id}/diff?compare_to=` — surface drift vs another scan of the same project (default: previous scan); params diff is `endpoint?name` strings,
- `/scans/{id}/coverage` gains a `surface` block (`endpoints_total/assessed`, `parameters_total/assessed`).

Coverage semantics: an endpoint is *assessed* iff persisted `AssessmentTest` rows (status `executed` / `validated` / `failed`) produced observations at that endpoint (`AssessmentTest.endpoint` normalized or its `observation_ids` subjects).

## Slice 3 — Continuous scheduling

### Storage

- `Scan.source_schedule_id` FK-ish column + index (SQLite cannot ALTER to add an inline FK — migration documents this; ORM keeps the FK for non-SQLite backends, application lookups enforce integrity),
- `ScanSchedule` model (`scan_schedules`): `user_id`, `project_id`, `name`, `target`, `cadence` (hourly/daily/weekly), `interval`, `enabled`, `next_run_at`, `last_run_at`, `last_run_status`, `last_scan_id`, `config`, timestamps.
- Migration head **`b2a9c4e5f6d8_phase12_schedules`** (down `e6f8a1c3d5b7`, additive; `verify_schema` picks the table up automatically from `Base.metadata`).

### Loop

`app/execution/schedule_loop.py`:
- `next_run_at(cadence, interval, after)` — deterministic recurrence,
- `scheduler_tick(db)` — finds due enabled schedules, skips any whose `last_scan_id` is still live (non-terminal stage via `lifecycle.TERMINAL_STAGES`), enqueues a **fresh** `Scan` (never reuses a schedule as a scan) with `source_schedule_id` + `schedule_cadence`, a `ScanAttempt(trigger="schedule")`, `_seed_progress`, then `trigger_background_scan`, and books `last_run_*` / `next_run_at` on the schedule,
- `run_scheduler_loop` (per-tick session), `start_scheduler` (daemon thread, opt-out via `settings.scheduler_enabled`, default on). `app/main.py` starts it at startup and holds a stop event for shutdown; tests run with `SCHEDULER_ENABLED=false` (set in `conftest.py` before app imports).

### API

`app/api/schedules.py` — `GET/POST /schedules`, `PATCH/DELETE /schedules/{id}` (delete = soft disable), `GET /schedules/{id}/scans`. Create is scope-checked (out-of-scope target → 403); cross-user access → 404 (platform convention).

## Invariants preserved

- No observation → no hypothesis execution → no finding.
- No deterministic evidence → no verified finding.
- Endpoint counts include any observed HTTP(S) subject (incl. api_document/script_asset URLs) — honest inventory.
- OpenAPI `servers[0]` out of scope → fall back to the in-scope document origin (still parsed).
- Cross-user resources → 404.

## Tests

`tests/test_phase12_surface.py` (16) and `tests/test_phase12_scheduling.py` (7). Combined regression (phase7 pinned + phase11 + phase9 granular + schema + imports) = **53 passed**. `tests/test_schema.py` updated (head + expected table set).