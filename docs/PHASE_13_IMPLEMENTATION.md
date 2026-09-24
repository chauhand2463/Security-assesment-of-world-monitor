# PHASE 13 — Production Dashboard Redesign (Implementation)

Status: implemented; production build verified (`npm run build`).

## Overview

The dashboard is reorganised around the **observed surface** delivered by
Phase 12: two dedicated scan-scoped pages (`/surface`, `/coverage`), an
expanded Overview that answers "what did the latest assessment actually see and
assess", and a typed client-side API layer that mirrors the backend response
shapes 1:1.

## Layout / navigation

`src/layouts/DashboardLayout.tsx` — the **Inventory** group now reads:

- Assets (`/assets`)
- Attack Surface (`/surface`)
- Coverage (`/coverage`)
- Tools (`/tools`)

`src/App.tsx` registers `<Route path="/surface">` and `<Route path="/coverage">`
inside the authenticated gate. Both pages accept and honour a `?scan=<id>` query
parameter for deep links (e.g. from the Overview / Coverage CTA).

## Typed API layer (`src/api.ts`)

New interfaces mirroring the backend payloads exactly:

- `SurfaceEndpoint`, `SurfaceParameter`, `SurfaceHost`, `SurfaceContext`,
  `SurfaceCoverage`, `SurfaceSnapshot`, `DiscoveryAsset`
- `AssessmentTask`, `AssessmentPlan`, `TimelineItem`, `TimelineResponse`
- `SurfaceDiff`, `ScanCoverageResponse`, `ScheduleRow`

Typed helpers (`getScanSurface`, `getScanEndpoints`, `getScanParameters`,
`getAssessmentPlan`, `getScanTimeline`, `getScanDiff`, `getScanCoverage`,
`listSchedules`) wrap the existing authenticated `apiFetch`; they return `T | null`
on transport/HTTP failure so pages degrade to honest empty states.

## Pages

### `src/pages/AttackSurface.tsx` (`/surface`)

The observed surface of one assessment, in production-friendly sections:

- redaction notice (values / credential material / methods never inferred),
- stat tiles (endpoints, parameters, hosts, API documents, script assets),
- endpoint + parameter **coverage gauges** (assessed / observed),
- host context cards (schemes, explicit ports, kind flags, first/last seen),
- endpoints table (`url`, scheme, param count, source chips, last seen),
- parameters table (name, `value_shape`, sensitive-name hint, sources),
- API documents + script assets discovery panels.

Uses the shared `ScanPicker` component so the page is scan-scoped without its
own nav.

### `src/pages/Coverage.tsx` (`/coverage`)

"Observed vs actually assessed" per assessment:

- headline metrics (scan coverage %, tools completed, endpoints/parameters assessed),
- the **deterministic assessment program** (`assessment-plan`) with planned/skipped
  filters and a registry-coverage bar,
- observed dimensions (hosts / ports / URLs chips + capture tools),
- surface coverage bars,
- **surface drift** (`diff` vs previous scan; added/removed endpoints & parameters).

### `src/pages/Dashboard.tsx` (Overview)

Added a **Latest observed surface** panel above the security-score block: after
`/scans/list` resolves, the newest assessment's `/coverage` is fetched and its
`surface` block renders assessed/total gauges for endpoints and parameters,
linking through to the full `/coverage?scan=<id>` page.

## Shared component

`src/components/ScanPicker.tsx` — dropdown of the user's assessments (newest
first, `#id · target · status`), auto-selects `?scan=` if present, else the
latest run; shows empty state when there are no assessments.

## Verification

- `tsc` and `vite build` both pass (only pre-existing chunk-size warning from the
  `@tabler/icons-react` barrel import).
- Backend shape drift is prevented by the typed interfaces above; backend tests
  remain green (Phase 12 suites + schema + imports = 33 passed).