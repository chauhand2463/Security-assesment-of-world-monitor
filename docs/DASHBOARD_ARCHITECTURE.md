# DASHBOARD_ARCHITECTURE

How the production dashboard is organised after Phases 9–13.

## Frontend layout

`src/layouts/DashboardLayout.tsx` renders the app shell around the authed
router. Navigation groups fetch their own live context:

- **Header** — brand, back button, simulation/live badge (`/tools/inventory`),
  user chip (`/auth/me`), logout (`/auth/logout`).
- **Sidebar** — `NAV_GROUPS` (Operations / Inventory / Assistant / Workspace)
  with the shared `layoutId="nav-active"` active pill, plus the authorized-scope
  card (`/scans/scope`).
- Inventory group: Assets, **Attack Surface**, **Coverage**, Tools.

Routes are registered in `src/App.tsx`; both scan-scoped pages accept a
`?scan=<id>` deep link.

## Pages vs data sources

| Page | Route | Feeds |
| --- | --- | --- |
| Overview | `/` | `/scans/list`, `/scans/summary`, `/dashboard/summary`, + latest scan `/scans/{id}/coverage` → `surface` |
| Assessments | `/scans` | `/scans/list`, `/scans/{id}`, SSE `/scans/{id}/events`, `/scans/{id}/assessment`, `/scans/{id}/observations`, `/scans/{id}/assets`, `/scans/{id}/report` |
| Assessment detail | `/scans/:id` | `/scans/{id}`, `/execution-plan`, `/executions`, `/observations`, `/findings`, `/assessment`, SSE |
| Attack Surface | `/surface` | `/scans/{id}/surface` |
| Coverage | `/coverage` | `/scans/{id}/coverage`, `/assessment-plan`, `/diff` |
| Findings | `/findings` | `/findings/list` etc. |
| Assets | `/assets` | `/auth/assets` (graph topology) |
| World Monitor | `/world-monitor` | world-monitor API |
| Tools / Settings / Chat / Knowledge / Reports | — | respective APIs |

## Typed API contract

`src/api.ts` centralises auth (`getToken` / `apiFetch` / `authUrl`), the 401
side-effect (`onUnauthorized`), and Phase 12/13 typed helpers wrapping the
backend shapes (`SurfaceSnapshot`, `AssessmentPlan`, `SurfaceDiff`,
`ScanCoverageResponse`, `ScheduleRow`, …). Because these interfaces mirror the
FastAPI payloads exactly, backend shape changes surface as `tsc` errors at build
time rather than as runtime render bugs.

## Cross-cutting UX rules

- Pages never invent data: every card/table has an honest empty state that
  says what would populate it, and every metric label states its derivation
  ("assessed", "observed", "persisted").
- Shared primitives: `PageHeader`, `DataTable`, `EmptyState`, `ErrorState`,
  `Skeleton*`, `Reveal`, format helpers, and the new `ScanPicker`.
- `framer-motion` handles page transitions / nav pill; `recharts` and
  `@xyflow/react` are available for charts and the asset topology graph.
- Scan-scoped pages default to the latest assessment and allow explicit
  selection — no global "current scan" coupling like the older assessments page.