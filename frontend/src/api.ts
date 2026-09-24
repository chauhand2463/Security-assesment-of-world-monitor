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
/* Phase 12/13 typed API surface. Every row is derived from persisted         */
/* observations; nothing returned by these helpers is ever guessed.           */
/* ------------------------------------------------------------------------- */

export async function getJSON<T>(path: string): Promise<T | null> {
  try {
    const res = await apiFetch(path);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export interface SurfaceEndpoint {
  url: string;
  scheme: string;
  host: string;
  method: string | null; // always null — never inferred from an observed URL
  sources: string[];
  kinds: string[];
  observation_ids: number[];
  first_seen: string | null;
  last_seen: string | null;
  parameter_count: number;
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
  type: string;
  data: Record<string, unknown>;
  created_at: string;
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

export interface ScheduleRow {
  id: number;
  user_id: string;
  project_id: number | null;
  name: string;
  target: string;
  cadence: 'hourly' | 'daily' | 'weekly';
  interval: number;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  last_scan_id: number | null;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

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

export const listSchedules = () => getJSON<ScheduleRow[]>('/schedules');