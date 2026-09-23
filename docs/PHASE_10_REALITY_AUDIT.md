# Phase 10 — Reality Audit (independent baseline re-verification)

**Date:** 2026-09-23
**Method:** the audit re-derives every claim from the authoritative implementation
and the schema — **never** from `README.md`, the docs, or my own prose. Each
section states where the behaviour is guaranteed (file:line) and what a
reproducing command observes. The two Phase 10 invariants are absolute:

1. **No real observation → no finding.** A finding row only ever exists when a
   persisted `observations` row backs it.
2. **No verified evidence → no verified finding.** Nothing outside a recorded
   deterministic validation is presented as "confirmed".

---

## 1. Repo identity (what is where)

| Area | Location | Notes |
| --- | --- | --- |
| Backend | `backend/` (FastAPI, SQLAlchemy, Alembic) | venv at `backend/venv` |
| Frontend | `frontend/` (React 19 + Vite + TS) | `src/api.ts` is thin transport only |
| Database migrations | `backend/alembic/versions/` | current head `e6f8a1c3d5b7` |
| Tests | `backend/tests/` | **407** `def test_*` functions (55 files) measured 2026-09-23 |
| Docs | `docs/` | PHASE_1..PHASE_9, SIH, EVIDENCE_MODEL, FINDING_LIFECYCLE, ASSESSMENT_REPORTING |

The task spec's `infra/`, `rules/` and `mock-world-monitor/` directories
**do not exist** anywhere in the repository root (`ls`: `.agents`, `.git`,
`backend`, `docs`, `frontend`, `venv`, `_t.pdf`, `skills-lock.json`). No
provider, build recipe or mock service implements them; the World Monitor side
is 100 % real-HTTP (`backend/app/integrations/world_monitor/`).

**Reproduce:**
```
cd backend
venv\Scripts\python.exe -X dev -W ignore -m pytest tests -q      # 407 baseline
venv\Scripts\python.exe -c "from alembic.config import Config; from alembic.script import ScriptDirectory; s=ScriptDirectory.from_config(Config('alembic.ini')); print(list(s.get_heads()))"   # ['e6f8a1c3d5b7']
```

---

## 2. The 26 audit dimensions

### A. Scan lifecycle and state
Guaranteed where: `backend/app/orchestration/state.py` (`Scan.state` transition
table: `created/queued/preflight/running/validating/finalizing/completed/
completed_with_gaps/blocked/failed/cancelled`), `pipeline.py`
(`_move_state`, `_finish_terminal/_blocked/_cancelled/_failed`), API surface
`GET /scans/{id}/state`, `POST /scans/{id}/cancel`.

State transitions are **validated** (`SM.validate_transition`) before being
applied and persisting as a `scan_events` row with a reason. Terminals assign
legacy `stage`/`status` (`Completed`, `Partially Completed`, `Blocked`,
`Failed`, `Cancelled`). **Real-verified:** exercised by existing tests and the
scan-state endpoint. No transition is reachable through the raw DB.

### B. Background worker model
Guaranteed where: `backend/app/workers/tasks.py` — per-scan job entries in an
in-process `ThreadPoolExecutor` registry; `ScanJob` holds `thread`,
`cancel_requested`. Optional Celery path is inert unless `celery` is importable.

**Status: IMPLEMENTED.** Caveat: it is an in-process job registry, not a
persistent queue. A process restart abandons in-flight jobs (rows stay
`running`). Not a Phase 10 blocker, but recorded.

### C. Cancellation
Guaranteed where: `app/workers/tasks.py` (`ScanCancelled`, `ScanJob.cancel`),
`app/execution/runner.py` (bounded subprocess runner polls `cancel_check`),
`app/orchestration/executions.py` (`_run_adapter` passes `job.cancel_check`),
`pipeline.py` (`_check_cancel` between stage/tool boundaries).

**Gap resolved since baseline (10.3):** the scheduler is now bounded-parallel
(`group_plan`/`execute_batch`, `max_parallel_tools` clamped 1..8, stage-barrier
model — `pipeline.py:223-232`) and every non-legacy run goes through the
bounded runner with `job.cancel_check` (`executions.py:571-573`). **Remains:**
the legacy shell runners (`scanner_tools.ScannerAdapter.execute`,
`_LEGACY_RUNNERS[tool](target)` at `executions.py:481`) still call
`subprocess.run(timeout=…)` with **no** `cancel_check`, so a long legacy tool is
only stopped by its own timeout. → **PARTIAL for legacy shells, resolved for adapters.**

### D. Tool adapters
Guaranteed where: `app/tools/adapters/base.py` (`ExternalToolAdapter` contract:
`run(target, simulation, options, cancel_check)` → `ToolRunResult` with
redacted command, exit code, bounded stdout/stderr), `adapters/registry.py`
(nmap, nuclei, httpx, ffuf, nikto, sqlmap, testssl), `app/tools/inventory.py`
(real `which` + version probe, 5 s timeout, 60 s TTL cache),
`app/tools/scanner_tools.py` (legacy CLI wrappers; `shell=False`, arg arrays),
`app/orchestration/preflight.py` (`ToolReadiness` rows + per-scan `preflight_json`).

Redaction: `redact_command`, `SENSITIVE_ARG_FLAGS`, `safe_target`,
`as_redacted` on headers/keys. **Status: IMPLEMENTED** for the 7 adapters;
readiness vocabulary is `installed|missing|disabled|adapter_unavailable` (a
binary whose version probe fails is `installed` with `version=None`, or
`missing` when `which` fails — no `unhealthy/version_unknown/permission_error`
vocabulary yet). → IMPLEMENTED, vocabulary narrower than Phase 10 target.

### E. Subprocess execution / timeout
Guaranteed where: `app/execution/runner.py` — 512 KiB per-stream cap,
0.05 s poll, hard timeout, cancel poll, `RunTelemetry`;
`app/tools/scanner_tools.py` — fixed `BINARY_TIMEOUT_SECONDS`, list-args
(`shell=False`), Windows PATH discovery via `winreg`, `sanitize_input`.
Adapter retry-once only on timeout/execution-failed (`_TRANSIENT_STATUSES`).
No `shell=True` anywhere. → **IMPLEMENTED / safe.** Retry of the dangerous
opt-in tools (ffuf/nikto/sqlmap/testssl) is gated on explicit `tool_options`.

### F. Observations
Guaranteed where: `database/models.py` `Observation` (kind, subject,
`data_json`, `raw_output`, `observation_type`, `source`, `tool_version`,
`request_json`/`response_json` **redacted**, `fingerprint`, `status`,
`asset_id` Phase 9), `app/observations/normalize.py` (`build_observation`,
normalized endpoints, `<REDACTED>`, `SENSITIVE_HEADERS`/`SENSITIVE_KEYS`).

**Gap resolved since baseline (10.4):** migrations added `observations.tool_execution_id`
(FK to `tool_executions`) and `tool_executions` is the redacted, attributed run
ledger (`_begin_execution`/`_finish_execution`); every persist path now passes a
nullable `tool_execution_id` (`executions.py:222`), including the legacy shell
path (`_run_legacy` writes real execution rows with `command_redacted`,
attempt, duration, termination reason). **Remains:** the legacy probe persist
path (`_persist_legacy_observation`) still does **not** apply the full
`build_observation` normalization (no `observation_type`/`fingerprint`/
redaction layers on that path) — provenance of *which run* is now complete;
normalization parity on legacy rows is recorded, not retrofitted.

### G. Detection engine
Guaranteed where: `app/assess/finding_rules.py` (deterministic rules over
persisted observations: missing security headers, TLS/banner version hints,
outdated jQuery, nuclei observations), `app/assess/registry.py`,
`app/assess/detection_registry.py` (`DetectionRule`, `RuleRegistry`).
**Resolved since baseline (10.5):** rules are wrapped in a registry of records
with per-rule metadata + a registry fingerprint (`assess/detection_registry.py:30`).
→ RESOLVED.

### H. Finding lifecycle, verification, dedup, severity, evidence
Guaranteed where:
- Lifecycle: `app/assess/finding_lifecycle.py` — statuses
  candidate/validated/confirmed/rejected/duplicate/accepted/remediated/reopened
  with immutable `FindingStatusHistory` (actor, reason, from/to, timestamp).
- Verification: `app/assess/verification.py` — every re-check appends a
  `verifications` row (deterministic, persisted-observations only) and flips
  `verification_state` on the finding (`verification.py:91,134`); re-compute
  pass in `pipeline.py:389`; `GET /findings/{id}` returns `verification_state`
  + `verifications[]` (`findings.py:258`). Implements Phase 10.6: **no verified
  evidence → no verified state**.
- Dedup: one namespace — native findings and external candidates both key off
  the same `finding_fingerprint` (`app/observations/fingerprint.py:56`,
  `assess/engine.py:364-373`), so nuclei and native engine findings on the same
  issue collide by fingerprint. **Phase 10.7 resolved.**
- Severity: `app/assess/severity.py` — deterministic (category base +
  unauthenticated/requires_auth/boundary_crossed/data_exposure/repeatable/
  scope_limited). No inflation.
- Evidence: `FindingEvidence` rows with redacted request/response + hashes;
  `FindingObservationLink` provenance.
→ RESOLVED (verification engine + verification_state + cross-tool dedup).

### I. World Monitor
Guaranteed where: `app/integrations/world_monitor/provider.py`
(`WorldMonitorProvider` with `SafeHttpClient`, 8 s default timeout),
`health.py` (one scope-guarded real GET), `discovery.py` (`TargetConfig`,
`DiscoveryResult`, status vocabulary `reachable/unavailable/invalid_schema/
no_endpoints/error`), `models.py`, `normalizers.py`; API
`app/api/world_monitor.py` (create/list/get/delete/check/discover/inventory);
pipeline runner `executions.py::_run_world_monitor_discovery` with `_wm_guard`
and `_wm_target_config` (same-host cross-check: `base_url` vs `api_base_url`
vs `openapi_url` must share a host, else refused). Deployment identity mixing
is refused at both the API and the execution layer. **Resolved since baseline
(10.9):** transient failures (`_transient_error`, network-level `status==0`)
retry with bounded exponential backoff (`health.py:33`,
`discovery.py:274`), staleness is surfaced (`world_monitor.py:138`
`world_monitor_stale_after_seconds` → `_staleness` fresh/stale/never_checked;
never auto-re-probes) and `bridged_scans` lists only explicit
`scan_config.world_monitor.target_id` references. → **IMPLEMENTED / TESTED**
(`test_phase8_world_monitor_api.py` + `test_phase10_world_monitor_reliability.py`).
Scheduled refresh does not exist (discovery is explicit); surfaces honest statuses.

### J. SSE
Guaranteed where: `app/api/scans.py` — `GET /scans/{id}/events` (live, **DB
poll every 0.5 s**, diff-driven), `GET /scans/{id}/stream` (log tail),
`GET /scans/{id}/typed-events` (ordered replay with cursor/has_more).
`app/orchestration/events.py` — per-scan monotonic `seq`, typed event names
(state, stage, tool, preflight, progress, coverage, finding, validation, done,
error, + Phase 9 granular asset.discovered/observation.created/finding.candidate/
finding.verified/finding.rejected).

**Gap resolved since baseline (10.8):** the live `/events` channel accepts a
`Last-Event-ID` header (`scans.py:764-770`) and resumes exactly after that
cursor — a reconnecting EventSource client does not miss events. The channel is
still **poll-and-diff** (DB every 0.5 s) rather than a vertical push bus, which
is a transport detail, not a loss-of-events gap; `/stream` accepts the token via
`?token=` (documented EventSource constraint). → **RESOLVED** for cursor resume
(`test_phase10_sse_resume.py`).

### K. Dashboard aggregation
Guaranteed where: `app/api/dashboard.py` + `tests/test_phase9_dashboard.py`
`test_dashboard_relies_only_on_persisted_rows…` — every number derives from
persisted rows (observations/findings/assets summaries), never constants.
Scans dashboard `/scans/summary`, in-scan `/scans/{id}/coverage` also row-based.
→ **IMPLEMENTED / REAL-VERIFIED.**

### L. Reports
Guaranteed where: `app/reporting/builder.py` (deterministic, registry/config
fingerprints, limitations), `app/api/scans.py::/scans/{id}/report`,
`app/api/reports.py` (`ReportExport` with SHA-256 `content_hash`, has/props,
rendered html/md/pdf). In-scan pipeline report (`pipeline.py::_build_report`)
embeds preflight, stages, executions, coverage, ML advisory. → **IMPLEMENTED /
TESTED** (`test_phase9_report_exports`).

### M. Simulation pathways
Guaranteed where: `pipeline.py::orchestrate_scan_phase7(simulation=…)` —
`True` routes to the Phase 4 `orchestrate_scan(simulation=True)` (queues a
**simulated** run for sandbox/compat; tests + legacy SSE depend on it),
`False` is real-only. Phase 7 never fabricates. `app/config.py` default
`SIMULATION_MODE=False` (real by default at code level) but `.env.example`
transmits `SIMULATION_MODE=true` and `README.md` still claims *"Phase 2…
simulation default"* — **stale docs/env-template**, not stale code. The Phase 7
execution path never consults `settings.simulation_mode`, so no real scan can
silently become simulated if `.env` says so. → code IMPLEMENTED; docs drift.

### N. Hardcoded / sample data
Audited: `Scans.tsx` phase-guidance text is labels only; all counts come from
SSE/API. Backend seeds only `seed_defaults()` (admin bootstrap when env
configured; no sample scans/findings). No random/constant numbers feed
findings, coverage, health or tool status. Findings only via the rule engine
over persisted observations or the Phase 5 engine. → CLEAN. (Frontend has no
ScanDetail/Executions/Observations/Verification pages at all yet — a
completeness gap, not a fakery gap.)

### O. Race conditions
Observed at: `_run_stages` writes `ScanStage` rows while workers write
observations — writers are serialized by SQLite; counters are recomputed from
real rows (`MAX(observation.id)` watermark) so no double-counting drift.
`workers/tasks.py` registry is `dict` guarded by a `threading.Lock`.
`events.py` seq is per-scan counter — single-writer per scan in the current
**sequential** pipeline. **Parallelism does not exist yet**, so cross-thread
seq races are theoretical; once Phase 10.3 introduces concurrency, seq
allocation and progress/counter writes must be centralized (planned).

### P. Blocking operations
DB calls are synchronous (SQLAlchemy, default SQLite). Adapter/legacy I/O runs
inside worker threads (job registry), not the event loop. The SSE generators
poll DB every 0.5 s inside `async def` (small per-iteration work, `await
asyncio.sleep` — acceptable). No rendezvous/thread-per-request leak beyond the
bounded registry. → acceptable, will be re-checked under parallelism.

### Q. Security boundaries
- Subprocess: `shell=False`, argument arrays, `sanitize_input`, redacted
  command/headers, bounded output, hard timeout. ✓
- Scope: `app/assess/engine._scope_guard`, `App_agents.is_target_in_scope`,
  `_wm_guard`, `_wm_target_config` same-host refusal, target normalization
  (`database/schemas.py.normalize_target`). ✓
- Auth/RBAC: `app/core/auth.py`, bearer sessions with `token_hash`
  (no plaintext token storage), per-user ownership on every scan/target route.
  ✓
- Secrets: config module holds no secrets; tokens hashed; evidence redacted
  before persistence. ✓

### R. Test coverage
333 tests green baseline (2026-09-22 measured in Phase 9 audit and re-measured
as 333 `def test_*` on 2026-09-23). Named Phase 9 contracts cover granular
events, persisted-row dashboards, report exports, triage history, scan events,
pipeline state, tools inventory, WM register/check/delete, auth isolation.
**No Phase 10-named tests exist** (test_phase10_* to be added with each phase).

---

## 3. Phase 10 gap register (drives the implementation order)

| # | Gap | Evidence | Phase |
| --- | --- | --- | --- |
| G1 | **No parallel execution** — `pipeline.py:205` runs `for task in plan_tasks(config)` strictly sequentially; one tool at a time | `pipeline.py:205-229`, `executions.py:169` | 10.3 |
| G2 | **No `tool_execution_id` on `observations`** — cannot trace an observation to its exact run/command | `models.py` (no column) | 10.4 |
| G3 | Legacy probe persist path skips `build_observation` (no `observation_type`/`fingerprint`/redaction) | `executions.py:275-291` | 10.4 |
| G4 | Legacy shell runs are **not mid-process cancellable** (subprocess.run, no cancel_check) | `executions.py:33-40,473-519` | 10.3 |
| G5 | Live `/events` SSE is **poll-and-diff**, no `Last-Event-ID` resume | `scans.py:721-786` | 10.8 |
| G6 | No **verification engine** / no `Verification` rows / no `verification_state` on findings | `pipeline.py:338-400` | 10.6 |
| G7 | **Cross-tool dedup missing** — external candidates vs native findings use disjoint key namespaces | `assess/dedup.py` vs `executions.py` (`external:…`) | 10.7 |
| G8 | Detection rules are functions, not a **registry with fingerprint / per-rule metadata** | `assess/finding_rules.py` | 10.5 |
| G9 | Coverage = completed/total tasks only; no **dimension coverage** (ports/hosts/URLs observed) | `pipeline.py:509-519` | 10.11 |
| G10 | Frontend: **no ScanDetail/Executions/Observations/Verification pages**; parallel state not visualized | `frontend/src/pages` | 10.10 |
| G11 | Docs/env drift: README "Phase 2 default simulation", `.env.example` `SIMULATION_MODE=true` vs code default `false` | `README.md`, `.env.example`, `config.py:32` | 10.12 |
| G12 | Tool readiness vocabulary narrower (no `unhealthy/version_unknown/permission_error`) | `models.py::ToolReadiness` | 10.2 |

---

## 4. Recommendation (what Phase 10 must build, in order)

1. **10.2** — ScannerAdapter manifest contract over `adapters/registry.py`
   (probe/health/capabilities), extend ToolReadiness vocabulary. No behaviour
   rewrite.
2. **10.3** — bounded parallel scheduler over the existing `plan_tasks`
   (stage-barrier model, `max_parallel_tools`), centralized seq/counter writes,
   deep cancellation into legacy runs (bounded runner for legacy shells).
3. **10.4** — migration `observations.tool_execution_id`; provenance + full
   `build_observation` normalization (fingerprint/redaction) on every persist
   path; observation→execution→stage evidence chain.
4. **10.5** — DetectionRule registry (per-rule metadata + fingerprint) over the
   existing deterministic rules.
5. **10.6** — verification engine: candidate → `Verification` rows → only
   verified evidence flips `verification_state`; determininistic re-checks
   re-run on persisted observations only.
6. **10.7** — cross-tool correlation: one fingerprint namespace, merged
   evidence, status history preserved.
7. **10.8** — SSE: typed cursor + `Last-Event-ID` resume on `/events`
   (default behavior unchanged), consolidated on `scan_events`.
8. **10.9** — WM reliability: retry with backoff on transient network errors,
   staleness surfacing; bridge scan → target remains insight + explicit.
9. **10.10** — frontend evidence workspace (Scan Detail / Executions /
   Observations / Verification), parallel execution visualization from real
   rows only.
10. **10.11** — reports/dashboard: parallel execution timing + dimension
    coverage from real rows.
11. **10.12** — security+i18n pass, GPU-grade polish, docs/env drift fix.
12. **10.13/10.14/10.15** — full test suite + new test_phase10_*; real
    authorized acceptance scan (own host); final re-audit.

**One caveat for the acceptance scan:** standard probes are passive/quiet by
design (`TCP_PORT_PROBE_LIST` = 8 ports); a real scan of an authorized target
can be run with `SIMULATION_MODE=false` and `tools` opt-ins restricted, exactly
as the task's "own authorized target" clause allows.