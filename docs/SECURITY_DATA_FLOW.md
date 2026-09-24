# SECURITY_DATA_FLOW

End-to-end evidence flow through CyberAgent's assessment platform, described in
the same traceable order the engine runs it.

## 1. Scope (authorization boundary)

- Declared scope lives on the user's `Project.scope_json`. Targets outside it
  are rejected before any work begins (`403`; cross-user access to any resource
  returns `404`). Continuous schedules validate scope at creation **and** at
  every enqueue tick.

## 2. Observation (evidence creation)

Only real, executed tools may write observations. `_persist_observations`
writes `Observation` rows (`kind`, `subject`, `data_json`, `tool`, `source`,
`scan_id`) and emits typed events (`endpoint.discovered`,
`parameter.discovered`, `assessment.item`, `asset.discovered`).

- Phase 11 discovery and Phase 12 surface discovery parse raw bytes in memory;
  only the *facts* (`api_document`, `script_asset`, `api_endpoint_candidate`,
  `api_parameter_candidate`) are persisted. No YAML parsing (no PyYAML
  dependency) — YAML documents are recorded as `api_document` with
  `status: unsupported`.
- **Redaction invariant:** parameter **values** and credential material never
  leave the engine. Only parameter names + existence shapes (`present`/`empty`)
  appear in the surface inventory, and query-stripped endpoint URLs are
  canonicalised through `endpoint_key`.

## 3. Hypothesis (planning)

- `plan_surface` derives a deterministic assessment program from observed
  endpoints/parameters **only**; unobservable tests get a concrete `skipped`
  reason. The engine planner remains authoritative during a real run.
- `NO OBSERVATION → NO HYPOTHESIS EXECUTION → NO FINDING`. Tests only apply to
  endpoints/parameters that were actually observed.

## 4. Execution (deterministic checks)

- Executed tests write `AssessmentTest` rows (`status`, `endpoint`,
  `observation_ids`). A surface item counts as *assessed* only when persisted
  `executed` / `validated` / `failed` test rows produced observations at it.

## 5. Finding + verification

- Findings derive only from persisted evidence (`FindingObservationLink`).
- `NO DETERMINISTIC EVIDENCE → NO VERIFIED FINDING`. Verification checks replay
  persisted observations; the engine never auto-re-probes for verification.

## 6. Ledger, events, scheduling

- `ScanEvent` rows (payload on the `data` JSON column) replay the chronological
  surface/assessment timeline via SSE and `/scans/{id}/timeline`.
- `ScanSchedule` is a recurrence definition only. Each due tick enqueues a
  **fresh** `Scan` (with `source_schedule_id` provenance) through the normal
  pipeline — a schedule is never itself a scan.

## Dashboard guarantees

- Every number on the overview / surface / coverage pages is derived from the
  persisted rows above. Endpoint counts include any observed HTTP(S) subject
  (including `api_document` / `script_asset` URLs) — i.e. the inventory is
  honest about what was seen, and it makes no inference about methods or
  parameter values.