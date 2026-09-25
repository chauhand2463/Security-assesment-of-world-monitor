export const API_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  'http://127.0.0.1:8001';

const TOKEN_KEY = 'cyberagent_token';

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

type UnauthorizedHandler = () => void;

let unauthorizedHandler: UnauthorizedHandler | null = null;

export function onUnauthorized(handler: UnauthorizedHandler): void {
  unauthorizedHandler = handler;
}

function notifyUnauthorized(): void {
  clearToken();
  if (unauthorizedHandler) {
    unauthorizedHandler();
  }
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(options.headers || {});
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (res.status === 401) {
    notifyUnauthorized();
  }
  return res;
}

export function authUrl(path: string): string {
  const token = getToken();
  const sep = path.includes('?') ? '&' : '?';
  return `${API_URL}${path}${sep}token=${encodeURIComponent(token || '')}`;
}

/* ------------------------------------------------------------------------- */
/* Error vocabulary. Every consumer can distinguish the failure class so the  */
/* UI can say precisely what went wrong instead of a generic null.            */
/* ------------------------------------------------------------------------- */

export class ApiError extends Error {
  readonly kind: 'network' | 'http' | 'malformed' | 'unauthorized';
  readonly status: number | null;
  readonly detail: unknown;

  constructor(
    kind: 'network' | 'http' | 'malformed' | 'unauthorized',
    message: string,
    status: number | null = null,
    detail: unknown = null,
  ) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
    this.detail = detail;
  }
}

export type ApiResult<T> =
  | { ok: true; data: T; status: number }
  | { ok: false; error: ApiError };

export async function apiResult<T>(path: string, options: RequestInit = {}): Promise<ApiResult<T>> {
  let res: Response;
  try {
    res = await apiFetch(path, options);
  } catch {
    return {
      ok: false,
      error: new ApiError('network', 'Network request failed. Check that the backend is running.'),
    };
  }
  if (res.status === 401) {
    return {
      ok: false,
      error: new ApiError('unauthorized', 'Session expired. Sign in again.', 401),
    };
  }
  if (!res.ok) {
    let detail: unknown = null;
    try {
      detail = (await res.json()) as unknown;
    } catch {
      detail = null;
    }
    return {
      ok: false,
      error: new ApiError('http', `Request failed (${res.status}).`, res.status, detail),
    };
  }
  try {
    const data = (await res.json()) as T;
    return { ok: true, data, status: res.status };
  } catch {
    return { ok: false, error: new ApiError('malformed', 'Response was not valid JSON.') };
  }
}

/* Legacy helper: pages that only care "is there data" keep working unchanged. */
export async function getJSON<T>(path: string): Promise<T | null> {
  const result = await apiResult<T>(path);
  return result.ok ? result.data : null;
}

/* ------------------------------------------------------------------------- */
/* Typed API surface. Every row is derived from persisted state; nothing      */
/* returned by these helpers is ever guessed.                                 */
/* ------------------------------------------------------------------------- */

export interface SurfaceEndpoint {
  url: string;
  scheme: string;
  host: string;
  port: number; // explicit URL port or deterministic scheme default (443/80)
  method: string | null; // always null — never inferred from an observed URL
  sources: string[];
  kinds: string[];
  observation_ids: number[];
  first_seen: string | null;
  last_seen: string | null;
  parameter_count: number;
  assessed: boolean; // executed/validated/failed AssessmentTest rows reference this endpoint
  assessment_statuses: string[];
  assessment_tests: number;
}

export interface SurfaceParameter {
  endpoint: string;
  parameter: string;
  value_shape: 'present' | 'empty';
  value_sensitive: boolean;
  sources: string[];
  kinds: string[];
  observation_ids: number[];
  first_seen: string | null;
  last_seen: string | null;
  assessed: boolean;
  assessment_statuses: string[];
}

export interface DiscoveryAsset {
  id: number;
  url: string;
  kind: string;
  data: Record<string, unknown>;
  source?: string | null;
  observed_at: string | null;
}

export interface SurfaceHost {
  host: string;
  schemes: string[];
  ports: number[];
  kinds: string[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface SurfaceContext {
  target: string;
  hosts: SurfaceHost[];
  host_count: number;
  observation_count: number;
  http_subjects: number;
  observation_kinds: Record<string, number>;
  sources: string[];
  asset_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface SurfaceCoverage {
  endpoints_total: number;
  endpoints_assessed: number;
  parameters_total: number;
  parameters_assessed: number;
  note: string;
}

export interface SurfaceSnapshot {
  scan_id: number;
  target: string;
  context: SurfaceContext;
  endpoints: SurfaceEndpoint[];
  endpoint_count: number;
  parameters: SurfaceParameter[];
  parameter_count: number;
  api_documents: DiscoveryAsset[];
  script_assets: DiscoveryAsset[];
  coverage: SurfaceCoverage;
  note: string;
}

export interface AssessmentTask {
  test_id: string;
  name: string;
  category: string;
  active: boolean;
  status: 'planned' | 'skipped';
  reason: string;
  endpoints: string[];
  parameters: string[];
}

export interface AssessmentPlan {
  scan_id: number;
  target: string;
  generated_at: string;
  tests_total: number;
  tests_planned: number;
  tests_skipped: number;
  tasks: AssessmentTask[];
}

export interface TimelineItem {
  id: number;
  seq: number;
  type: string;
  data: Record<string, unknown>;
  created_at: string;
  source: string | null;
  target: string | null;
  status: string | null;
  reference: Record<string, number>;
}

export interface TimelineResponse {
  scan_id: number;
  items: TimelineItem[];
}

export interface SurfaceDiff {
  scan_id: number;
  compare_to: number | null;
  target?: string;
  endpoints_added: string[];
  endpoints_removed: string[];
  parameters_added: string[];
  parameters_removed: string[];
  endpoint_count_a?: number;
  endpoint_count_b?: number;
  note: string;
}

export interface ScanCoverageResponse {
  scan_id: number;
  target: string;
  coverage: number | null;
  completed_tasks: number;
  failed_tasks: number;
  total_tasks: number;
  completed_tools: number;
  total_tools: number;
  percent: number;
  planned_tasks: unknown[];
  security_score: number | null;
  dimensions: {
    hosts?: { distinct?: unknown[]; observed?: number; tools?: string[] };
    ports?: { distinct?: unknown[]; observed?: number; tools?: string[] };
    urls?: { distinct?: unknown[]; observed?: number; tools?: string[] };
  };
  surface: SurfaceCoverage;
}

export interface ScanRow {
  id: number;
  target: string;
  status: string;
  security_score: number | null;
  created_at: string | null;
  completed_at: string | null;
  assessment_type: string | null;
}

export interface ScanDetail {
  id: number;
  target: string;
  status: string;
  stage: string;
  security_score: number | null;
  coverage: number | null;
  progress: Record<string, unknown>;
  scan_config: Record<string, unknown>;
  assessment_type: string | null;
  authorization_acknowledged: boolean | null;
  created_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  error: string | null;
  logs: string | null;
  simulation: boolean;
  vulnerabilities: ScanFindingRow[];
  observations_count: number;
  dimensions: Record<string, unknown>;
  assessment: {
    coverage: Record<string, unknown> | null;
    tests: unknown[];
    sih: Record<string, unknown>;
  };
  tools: { name: string; status: string; raw_output: string | null }[];
}

export interface ScanObservationRow {
  id: number;
  tool: string | null;
  kind: string | null;
  subject: string | null;
  data: Record<string, unknown>;
  raw: string;
  created_at: string | null;
  observation_type: string;
  source: string | null;
  status: string | null;
  fingerprint: string | null;
  asset_id: number | null;
  request: Record<string, unknown> | null;
  response: Record<string, unknown> | null;
  tool_execution_id: number | null;
  provenance: {
    execution_id: number;
    tool: string;
    stage: string;
    attempt: number;
    status: string;
    duration_ms: number | null;
    parsed_observations: number;
    started_at: string | null;
    finished_at: string | null;
    exit_code: number | null;
    termination_reason: string | null;
  } | null;
}

export interface ScanFindingRow {
  id: number;
  title: string;
  severity: string;
  description: string | null;
  remediation: string | null;
  cve: string | null;
  cvss: string | null;
  owasp: string | null;
  mitre: string | null;
  cwe: string | null;
  rule_id: string | null;
  state: string;
  confidence: string | null;
  target: string | null;
  proof_of_concept: string | null;
  evidence: string | null;
  evidence_observation_ids: number[];
  resolved_at: string | null;
  category: string | null;
  endpoint: string | null;
  http_method: string | null;
  source_test: string | null;
  source_tool: string | null;
  validation_reason: string | null;
  impact: string | null;
  evidence_records: EvidenceRecord[];
  status: string;
  affected_component: string | null;
  parameter: string | null;
  cvss_version: string | null;
  cvss_vector: string | null;
  cvss_score: number | null;
  business_impact: string | null;
  technical_impact: string | null;
  impact_details: string | null;
  remediation_details: string | null;
  fingerprint: string | null;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ScanSummary {
  scans?: unknown;
  average_coverage?: number | null;
}

export interface AssessmentAggregate {
  total_findings: number;
  total_confirmed: number;
  total_candidates: number;
  total_validated: number;
  total_rejected: number;
  total_duplicates: number;
  total_accepted: number;
  total_remediated: number;
  total_reopened: number;
  by_status: Record<string, number>;
}

export interface AssessmentSummary {
  assessment_status: string;
  assessment_completeness: string;
  coverage: Record<string, unknown> | null;
  aggregate: AssessmentAggregate;
  headline: string;
  snapshot: Record<string, unknown> | null;
}

export interface FindingRow {
  id: number;
  scan_id: number;
  target: string;
  assessment_type: string | null;
  title: string;
  severity: string;
  status: string;
  state: string;
  category: string;
  sih_areas: string[];
  cwe: string | null;
  owasp: string | null;
  endpoint: string | null;
  http_method: string | null;
  parameter: string | null;
  affected_component: string | null;
  confidence: string | null;
  first_seen: string | null;
  last_seen: string | null;
  resolved_at: string | null;
}

export interface FindingDetail extends FindingRow {
  verification_state: string;
  description: string | null;
  rule_id: string | null;
  source_test: string | null;
  source_tool: string | null;
  validation_reason: string | null;
  remediation: string | null;
  remediation_details: string | null;
  impact_details: string | null;
  cvss: Record<string, unknown> | null;
  proof_of_concept: unknown[] | null;
  evidence: EvidenceRecord[];
  history: FindingHistoryEntry[];
  verifications: VerificationRow[];
}

export interface EvidenceRecord {
  id: number;
  observation_id: number | null;
  evidence_type: string;
  request: Record<string, unknown> | null;
  response: Record<string, unknown> | null;
  expected: string | null;
  actual: string | null;
  security_boundary: string | null;
  redaction_status: string;
  request_hash: string | null;
  response_hash: string | null;
  original_size: number | null;
  captured_size: number | null;
  truncated: boolean | null;
  integrity: string;
}

export interface FindingHistoryEntry {
  id: number;
  from_status: string | null;
  to_status: string;
  actor: string | null;
  reason: string | null;
  created_at: string | null;
}

export interface VerificationRow {
  id: number;
  method: string;
  status: string;
  rule_id: string | null;
  condition: string | null;
  reason: string | null;
  observation_ids: number[];
  completed_at: string | null;
  created_at: string | null;
}

export interface ToolExecutionRow {
  id: number;
  stage: string;
  tool: string;
  adapter: string | null;
  attempt: number;
  status: string;
  executable: string | null;
  tool_version: string | null;
  target: string | null;
  command_redacted: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  stdout_size: number | null;
  stderr_size: number | null;
  truncated: boolean;
  parsed_observations: number;
  cancellation_state: string | null;
  termination_reason: string | null;
  error_code: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface ToolExecutionSummary {
  tool: string;
  category: string;
  executions_total: number;
  statuses: Record<string, number>;
  observations_produced: number;
  last_execution_at: string | null;
  last_status: string | null;
  scans_touched: number;
}

export interface ToolExecutionLedger {
  tools: ToolExecutionSummary[];
  totals: {
    executions: number;
    observations_produced: number;
    completed: number;
    failed: number;
    timeout: number;
    not_installed: number;
    parse_failed: number;
    skipped: number;
    cancelled: number;
  };
  simulation_mode: boolean;
}

export interface ToolInventoryRow {
  tool: string;
  binary: string | null;
  installed: boolean;
  path: string | null;
  version: string | null;
  category: string;
  health_status: string;
  note: string | null;
}

export interface ToolInventoryResponse {
  tools: ToolInventoryRow[];
  simulation_mode: boolean;
  simulated: boolean;
}

export interface ScheduleRow {
  id: number;
  name: string | null;
  target: string;
  cadence: 'hourly' | 'daily' | 'weekly';
  interval: number;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  last_scan_id: number | null;
  last_scan_state: string | null;
  created_at: string | null;
}

export interface ScheduleScanRow {
  id: number;
  target: string;
  status: string;
  stage: string | null;
  state: string | null;
  created_at: string | null;
  completed_at: string | null;
}

export interface DashboardSummary {
  findings_lifecycle: Record<string, number>;
  findings_by_severity: Record<string, number>;
  findings_by_rule: Record<string, number>;
  confirmed_findings: number;
  candidate_findings: number;
  scans_total: number;
  scans_by_status: Record<string, number>;
  coverage_trend: { scan_id: number; target: string; coverage: number; created_at: string | null }[];
  cadence: Record<string, number>;
  observation_count: number;
  observations_by_scan: Record<string, number>;
  assets_total: number;
  assets_by_type: Record<string, number>;
  recent_findings: {
    id: number;
    scan_id: number;
    title: string;
    severity: string;
    status: string;
    category: string;
    endpoint: string | null;
    evidence_note: string;
  }[];
}

/* ---- scans ---- */

export const getScan = (scanId: number | string) => getJSON<ScanDetail>(`/scans/${scanId}`);
export const getScanList = () => getJSON<ScanRow[]>('/scans/list');
export const getScanSummary = () => getJSON<Record<string, unknown>>('/scans/summary');
export const getScanCoverageOverview = () => getJSON<ScanSummary>('/scans/coverage');
export const getScanObservations = (scanId: number | string) =>
  getJSON<ScanObservationRow[]>(`/scans/${scanId}/observations`);
export const getScanFindingsRow = (scanId: number | string) =>
  getJSON<ScanFindingRow[]>(`/scans/${scanId}/findings`);
export const getScanExecutions = (scanId: number | string) =>
  getJSON<ToolExecutionRow[]>(`/scans/${scanId}/executions`);
export const getAssessmentSummary = (scanId: number | string) =>
  getJSON<AssessmentSummary>(`/scans/${scanId}/assessment`);

export const getScanSurface = (scanId: number | string) =>
  getJSON<SurfaceSnapshot>(`/scans/${scanId}/surface`);

export const getScanEndpoints = (scanId: number | string) =>
  getJSON<{ scan_id: number; endpoints: SurfaceEndpoint[] }>(`/scans/${scanId}/surface/endpoints`);

export const getScanParameters = (scanId: number | string) =>
  getJSON<{ scan_id: number; parameters: SurfaceParameter[] }>(`/scans/${scanId}/surface/parameters`);

export const getAssessmentPlan = (scanId: number | string) =>
  getJSON<AssessmentPlan>(`/scans/${scanId}/assessment-plan`);

export const getScanTimeline = (scanId: number | string) =>
  getJSON<TimelineResponse>(`/scans/${scanId}/timeline`);

export const getScanDiff = (scanId: number | string, compareTo?: number | string) =>
  getJSON<SurfaceDiff>(
    compareTo ? `/scans/${scanId}/diff?compare_to=${compareTo}` : `/scans/${scanId}/diff`
  );

export const getScanCoverage = (scanId: number | string) =>
  getJSON<ScanCoverageResponse>(`/scans/${scanId}/coverage`);

/* ---- findings ---- */

export interface FindingsFilter {
  severity?: string;
  status?: string;
  category?: string;
  sih_area?: string;
  assessment_id?: number | null;
  limit?: number;
  offset?: number;
}

export const listFindings = (filters: FindingsFilter = {}) => {
  const params = new URLSearchParams();
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.status) params.set('status', filters.status);
  if (filters.category) params.set('category', filters.category);
  if (filters.sih_area) params.set('sih_area', filters.sih_area);
  if (filters.assessment_id) params.set('assessment_id', String(filters.assessment_id));
  params.set('limit', String(filters.limit ?? 100));
  params.set('offset', String(filters.offset ?? 0));
  const qs = params.toString();
  return getJSON<{ total: number; limit: number; offset: number; findings: FindingRow[] }>(
    qs ? `/findings?${qs}` : '/findings'
  );
};

export const getFinding = (findingId: number) => getJSON<FindingDetail>(`/findings/${findingId}`);

export const getFindingEvidence = (findingId: number) =>
  getJSON<{ finding_id: number; evidence: EvidenceRecord[] }>(`/findings/${findingId}/evidence`);

export const triageFinding = (findingId: number, action: string, reason?: string) =>
  apiResult<{
    id: number;
    status: string;
    state: string;
    updated_at: string | null;
    resolved_at: string | null;
  }>(`/findings/${findingId}/triage`, {
    method: 'POST',
    body: JSON.stringify({ action, reason: reason ?? null }),
  });

/* ---- dashboard ---- */

export const getDashboardSummary = () => getJSON<DashboardSummary>('/dashboard/summary');

/* ---- tools ---- */

export const getToolsInventory = () => getJSON<ToolInventoryResponse>('/tools/inventory');
export const getToolsExecutions = () => getJSON<ToolExecutionLedger>('/tools/executions');

/* ---- schedules ---- */

export const listSchedules = () => getJSON<ScheduleRow[]>('/schedules');

export interface ScheduleCreatePayload {
  target: string;
  cadence: 'hourly' | 'daily' | 'weekly';
  interval: number;
  name?: string | null;
  enabled?: boolean;
  config?: Record<string, unknown> | null;
}

export interface ScheduleUpdatePayload {
  enabled?: boolean;
  cadence?: 'hourly' | 'daily' | 'weekly';
  interval?: number;
  name?: string | null;
}

export const createSchedule = (payload: ScheduleCreatePayload) =>
  apiResult<ScheduleRow>('/schedules', { method: 'POST', body: JSON.stringify(payload) });

export const updateSchedule = (scheduleId: number, payload: ScheduleUpdatePayload) =>
  apiResult<ScheduleRow>(`/schedules/${scheduleId}`, { method: 'PATCH', body: JSON.stringify(payload) });

export const deleteSchedule = (scheduleId: number) =>
  apiResult<{ id: number; deleted: boolean; disabled: boolean }>(`/schedules/${scheduleId}`, {
    method: 'DELETE',
  });

export const runSchedule = (scheduleId: number) =>
  apiResult<{ schedule_id: number; scan_id: number; status: string; message: string }>(
    `/schedules/${scheduleId}/run`,
    { method: 'POST' }
  );

export const getScheduleScans = (scheduleId: number) =>
  getJSON<ScheduleScanRow[]>(`/schedules/${scheduleId}/scans`);