import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Activity,
  Terminal,
  FileText,
  ShieldCheck,
  Scale,
  Cpu,
  Boxes,
  Globe,
  ChevronRight,
  Layers,
  GitBranch,
  Network,
} from 'lucide-react';
import { apiFetch, authUrl } from '../api';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { SkeletonPanel } from '../components/Skeleton';
import { formatDateTime, humanDuration } from '../components/format';
import { Phase7Console } from '../components/Phase7Console';

type WorkspaceTab = 'overview' | 'execution' | 'executions' | 'observations' | 'verification' | 'console';

const VERIFICATION_TONES: Record<string, string> = {
  unverified: 'text-faint border-line',
  verified: 'text-accent border-accent/40 bg-accent/5',
  failed: 'text-critical border-critical/40 bg-critical/5',
  verification_pending: 'text-medium border-warn/40 bg-warn/5',
};

const LIFECYCLE_TONES: Record<string, string> = {
  candidate: 'text-faint',
  validated: 'text-accent',
  confirmed: 'text-critical',
  rejected: 'text-faint',
  duplicate: 'text-faint',
  accepted: 'text-medium',
  remediated: 'text-accent',
  reopened: 'text-medium',
};

function maxConcurrency(exs: any[]): number {
  const intervals = exs
    .filter((e: any) => e.started_at && e.finished_at)
    .map((e: any) => [new Date(e.started_at).getTime(), new Date(e.finished_at).getTime()]);
  let max = 0;
  for (const [s, f] of intervals) {
    let c = 0;
    for (const [s2, f2] of intervals) {
      if (s2 <= f && s <= f2) c += 1;
    }
    max = Math.max(max, c);
  }
  return max;
}

export const ScanDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const scanId = Number(id);

  const [scan, setScan] = useState<any | null>(null);
  const [plan, setPlan] = useState<any | null>(null);
  const [executions, setExecutions] = useState<any[]>([]);
  const [observations, setObservations] = useState<any[]>([]);
  const [findingRows, setFindingRows] = useState<any[]>([]);
  const [assessmentSummary, setAssessmentSummary] = useState<any | null>(null);
  const [findingDetails, setFindingDetails] = useState<Record<number, any>>({});
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<WorkspaceTab>('overview');
  const [consoleMode, setConsoleMode] = useState<'classic' | 'phase7'>('classic');
  const [liveEvents, setLiveEvents] = useState<string[]>([]);
  const [notFound, setNotFound] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [scanRes, planRes, exRes, obsRes, findRes, assessRes] = await Promise.all([
        apiFetch(`/scans/${scanId}`),
        apiFetch(`/scans/${scanId}/execution-plan`),
        apiFetch(`/scans/${scanId}/executions`),
        apiFetch(`/scans/${scanId}/observations`),
        apiFetch(`/scans/${scanId}/findings`),
        apiFetch(`/scans/${scanId}/assessment`),
      ]);
      if (!scanRes.ok) {
        const errData = await scanRes.json().catch(() => null);
        if (scanRes.status === 404) setNotFound(true);
        setError(errData?.detail || 'Failed to load scan detail.');
        return;
      }
      setScan(await scanRes.json());
      setPlan(planRes.ok ? await planRes.json() : null);
      setExecutions(exRes.ok ? await exRes.json() : []);
      setObservations(obsRes.ok ? await obsRes.json() : []);
      setFindingRows(findRes.ok ? await findRes.json() : []);
      setAssessmentSummary(assessRes.ok ? await assessRes.json() : null);
      startSSEStream(scanId);
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const startSSEStream = (sid: number) => {
    const es = new EventSource(authUrl(`/scans/${sid}/events`));
    eventSourceRef.current = es;
    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'error') {
          setLiveEvents((prev) => [...prev, `[Error] ${data.error}`]);
          return;
        }
        if (data.type === 'stage') {
          setScan((prev: any) => (prev ? { ...prev, stage: data.stage, status: data.status } : prev));
          setLiveEvents((prev) => [...prev, `[Stage] ${data.stage} (${data.status})`]);
        }
        if (data.type === 'tool') {
          setLiveEvents((prev) => [...prev, `[Tool] ${data.tool} -> ${data.status}`]);
        }
        if (data.type === 'finding') {
          setLiveEvents((prev) => [...prev, `[Finding] ${data.severity}: ${data.title}`]);
        }
        if (data.type === 'progress') {
          setScan((prev: any) =>
            prev ? { ...prev, coverage: data.coverage, security_score: data.security_score } : prev
          );
        }
        if (data.type === 'done') {
          setScan((prev: any) =>
            prev
              ? {
                  ...prev,
                  status: data.status,
                  stage: data.stage,
                  coverage: data.coverage,
                  security_score: data.security_score,
                }
              : prev
          );
          setLiveEvents((prev) => [...prev, `[Done] ${data.status} — coverage ${data.coverage ?? 0}%`]);
          es.close();
          eventSourceRef.current = null;
        }
      } catch (err) {
        console.error('Error parsing SSE event:', err);
      }
    };
    es.onerror = () => {
      es.close();
      eventSourceRef.current = null;
    };
  };

  useEffect(() => {
    setLoading(true);
    setNotFound(false);
    setError('');
    setScan(null);
    setPlan(null);
    setExecutions([]);
    setObservations([]);
    setFindingRows([]);
    setAssessmentSummary(null);
    setFindingDetails({});
    setLiveEvents([]);
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    fetchAll();
    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, [fetchAll, scanId]);

  const loadFindingDetail = async (fid: number) => {
    if (findingDetails[fid]) return;
    try {
      const res = await apiFetch(`/findings/${fid}`);
      if (res.ok) {
        const data = await res.json();
        setFindingDetails((prev) => ({ ...prev, [fid]: data }));
      }
    } catch (err) {
      console.error('Error fetching finding detail:', err);
    }
  };

  const handleToggleVuln = (fid: number) => {
    const next = expandedVuln === fid ? null : fid;
    setExpandedVuln(next);
    if (next !== null) loadFindingDetail(fid);
  };

  if (notFound) {
    return (
      <div className="space-y-6">
        <ErrorState
          message="This assessment does not exist or is not owned by your account."
          onRetry={() => navigate('/scans')}
        />
      </div>
    );
  }

  const dims = scan?.dimensions || null;
  const wmBridge = scan?.scan_config?.world_monitor?.target_id ?? null;
  const planTools = (plan?.plan || []).flatMap((g: any) =>
    (g.tools || []).map((tool: string) => ({ stage: g.stage, tool }))
  );
  const exStatusFor = (stage: string, tool: string) => {
    const row = executions.find((e: any) => e.stage === stage && e.tool === tool);
    return row ? row.status : null;
  };
  const planned = plan?.planned_tools ?? planTools.length;
  const doneCount = (plan?.completed_tools ?? 0) + (plan?.failed_tools ?? 0) + (plan?.skipped_tools ?? 0);
  const progressPct = planned > 0 ? Math.min(100, Math.round((doneCount / planned) * 100)) : 0;
  const exsByStage = (stage: string) => executions.filter((e: any) => e.stage === stage);
  const verificationCounts = findingRows.reduce<Record<string, number>>((acc, f) => {
    const key = (f.verification_state || 'unverified').toLowerCase();
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const TAB_ITEMS: { id: WorkspaceTab; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <Activity className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'execution', label: 'Execution plan', icon: <GitBranch className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'executions', label: 'Executions', icon: <Terminal className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'observations', label: 'Observations', icon: <FileText className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'verification', label: 'Verification', icon: <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'console', label: 'Console', icon: <Cpu className="w-3.5 h-3.5" aria-hidden="true" /> },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Assessments / Detail"
        title={scan ? scan.target : 'Assessment detail'}
        description={
          scan
            ? `Full detail for assessment #${scan.id} — coverage, execution, evidence and verification.`
            : 'Loading assessment detail…'
        }
        actions={
          <button
            onClick={() => navigate('/scans')}
            className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
          >
            <ArrowLeft className="w-3 h-3" aria-hidden="true" />
            All assessments
          </button>
        }
      />

      {loading ? (
        <div className="space-y-4">
          <SkeletonPanel className="min-h-[160px]" />
          <SkeletonPanel className="min-h-[320px]" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={fetchAll} />
      ) : !scan ? (
        <EmptyState title="No assessment" description="This assessment could not be loaded." />
      ) : (
        <>
          {/* Header summary */}
          <div className="panel p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base font-semibold text-text">{scan.target}</h2>
                  <StatusBadge status={scan.status} />
                </div>
                <p className="mono-cell text-[10.5px] text-faint mt-1">
                  #{scan.id} · queued {formatDateTime(scan.created_at)}
                </p>
                <div className="flex flex-wrap items-center gap-2 mt-2">
                  <span className="mono-cell text-[10px] text-faint">stage: {scan.stage || 'queued'}</span>
                  <span className="mono-cell text-[10px] text-faint">mode: {scan.simulation ? 'simulation' : 'real'}</span>
                  {wmBridge != null && (
                    <span className="mono-cell inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/5 px-2 py-0.5 text-[10px] text-accent">
                      <Globe className="w-3 h-3" aria-hidden="true" />
                      bridged to World Monitor target #{wmBridge}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-6">
                <div className="text-right">
                  <p className="eyebrow">Coverage</p>
                  <p className="text-lg font-semibold text-text">
                    {scan.coverage !== null && scan.coverage !== undefined ? `${scan.coverage}%` : '—'}
                  </p>
                </div>
                <div className="text-right">
                  <p className="eyebrow">Security score</p>
                  <p className="text-lg font-semibold text-text">
                    {scan.security_score !== null && scan.security_score !== undefined ? `${scan.security_score}/100` : '—'}
                  </p>
                </div>
              </div>
            </div>

            {/* Pipeline lifecycle */}
            <div className="mt-4 pt-4 border-t border-line">
              <div className="flex items-center gap-1.5 mb-2.5">
                <Layers className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                <span className="text-[12.5px] font-semibold text-text">Pipeline lifecycle</span>
              </div>
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
                {[
                  { id: 'queued', label: 'Queued' },
                  { id: 'starting', label: 'Starting' },
                  { id: 'recon', label: 'Recon' },
                  { id: 'discovery', label: 'Discovery' },
                  { id: 'service_scan', label: 'Service Scan' },
                  { id: 'http_scan', label: 'HTTP Scan' },
                  { id: 'vulnerability_scan', label: 'Vulnerability Scan' },
                  { id: 'analysis', label: 'Analysis' },
                  { id: 'reporting', label: 'Reporting' },
                ].map((st, idx, arr) => {
                  const cur = String((scan.stage || 'queued').toLowerCase());
                  const done = arr.findIndex((s) => s.id === cur) > idx || ['completed', 'partial', 'failed', 'cancelled'].includes(cur);
                  const active = arr.findIndex((s) => s.id === cur) === idx && !['completed', 'partial', 'failed', 'cancelled'].includes(cur);
                  return (
                    <div key={st.id} className="flex items-center gap-1.5 shrink-0">
                      <span
                        className={`mono-cell rounded-full border px-2.5 py-1 text-[9px] uppercase tracking-wide ${
                          active
                            ? 'border-accent/60 text-accent bg-accent/10'
                            : done
                            ? 'border-line-strong text-muted bg-surface-2'
                            : 'border-line text-faint'
                        }`}
                      >
                        {st.label}
                      </span>
                      {idx < arr.length - 1 && (
                        <span className="w-2 h-px bg-line" />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Tab bar */}
          <div className="flex items-center gap-1 overflow-x-auto border-b border-line -mb-px">
            {TAB_ITEMS.map((t) => {
              const active = tab === t.id;
              const count =
                t.id === 'executions'
                  ? executions.length
                  : t.id === 'observations'
                  ? observations.length
                  : t.id === 'verification'
                  ? findingRows.length
                  : null;
              return (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`inline-flex cursor-pointer items-center gap-1.5 rounded-t-lg border-b-2 px-3 py-2 text-[11.5px] transition-colors duration-500 ease-spring ${
                    active ? 'border-accent text-text' : 'border-transparent text-faint hover:text-muted'
                  }`}
                  aria-selected={active}
                >
                  {t.icon}
                  {t.label}
                  {count !== null && count > 0 && (
                    <span className="mono-cell rounded-full border border-line px-1.5 text-[9px]">{count}</span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Overview */}
          {tab === 'overview' && (
            <div className="space-y-4">
              {/* Dimension coverage (Phase 10.11) */}
              <div className="panel p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-1.5">
                    <Network className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                    <h3 className="text-[12.5px] font-semibold text-text">Observed dimensions</h3>
                  </div>
                  {dims?.scan_target_observed ? (
                    <span className="mono-cell text-[10px] text-accent">scan target observed: {dims.scan_target_observed}</span>
                  ) : dims ? (
                    <span className="mono-cell text-[10px] text-faint">scan target not observed</span>
                  ) : null}
                </div>
                {!dims ? (
                  <p className="text-[11px] text-faint">No observation data persisted for this assessment yet.</p>
                ) : (
                  <>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <DimensionCard label="Hosts" dim={dims.hosts} />
                      <DimensionCard label="Ports" dim={dims.ports} />
                      <DimensionCard label="URLs" dim={dims.urls} />
                    </div>
                    {dims.by_tool && Object.keys(dims.by_tool).length > 0 && (
                      <div className="mt-3 border-t border-line pt-3">
                        <p className="eyebrow mb-2">Contribution by tool (from real observations)</p>
                        <div className="flex flex-wrap gap-1.5">
                          {Object.entries(dims.by_tool).map(([tool, v]: any) => (
                            <span key={tool} className="mono-cell rounded-lg border border-line px-2 py-0.5 text-[10px] text-muted">
                              {tool}: {v.observations} obs · {v.hosts} host · {v.ports} port · {v.urls} url
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>

              {/* Execution plan summary (parallel viz entry) */}
              <div className="panel p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-1.5">
                    <GitBranch className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                    <h3 className="text-[12.5px] font-semibold text-text">Execution summary</h3>
                  </div>
                  <button
                    onClick={() => setTab('execution')}
                    className="mono-cell cursor-pointer rounded-full border border-line px-3 py-1 text-[10px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
                  >
                    Open execution plan →
                  </button>
                </div>
                {!plan ? (
                  <p className="text-[11px] text-faint">No execution plan available yet.</p>
                ) : (
                  <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-3">
                    <KV label="Strategy" value={(plan.strategy || 'sequential').toLowerCase()} mono />
                    <KV label="Parallel bound" value={`${plan.max_parallel_tools ?? 1} tool(s)`} mono />
                    <KV
                      label="Status"
                      value={(plan.status || 'pending').replaceAll('_', ' ')}
                      mono
                    />
                    <KV label="Planned" value={String(planned)} mono />
                    <KV label="Completed" value={String(plan.completed_tools ?? 0)} mono />
                    <KV label="Failed / skipped" value={`${plan.failed_tools ?? 0} / ${plan.skipped_tools ?? 0}`} mono />
                  </div>
                )}
              </div>

              {/* Assessment summary */}
              {assessmentSummary?.headline && (
                <div className={`panel p-4 ${
                  assessmentSummary.assessment_status === 'completed'
                    ? 'border-accent/30 bg-accent/5'
                    : 'border-warn/30 bg-warn/5'
                }`}>
                  <p className="text-[11.5px] leading-relaxed text-text">{assessmentSummary.headline}</p>
                </div>
              )}
              {assessmentSummary?.aggregate && (
                <div className="panel p-4">
                  <p className="eyebrow mb-2">Lifecycle aggregate</p>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {Object.entries(assessmentSummary.aggregate.by_status || {}).map(
                      ([status, count]) =>
                        (count as number) > 0 && (
                          <span key={status} className={`mono-cell text-[10px] border border-line rounded-md px-2 py-0.5 ${LIFECYCLE_TONES[status] || 'text-faint'}`}>
                            {status}: {count as number}
                          </span>
                        )
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Execution plan (parallel state viz) */}
          {tab === 'execution' && (
            <div className="space-y-4">
              {!plan ? (
                <EmptyState
                  title="No execution plan"
                  description="The plan for this assessment has not been recorded yet."
                />
              ) : (
                <>
                  <div className="panel p-4">
                    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 mb-3">
                      <KV label="Strategy" value={(plan.strategy || 'sequential').toLowerCase()} mono />
                      <KV label="Bounded concurrency" value={`${plan.max_parallel_tools ?? 1} max`} mono />
                      <KV label="Status" value={(plan.status || 'pending').replaceAll('_', ' ')} mono />
                      {plan.duration_ms != null && <KV label="Duration" value={humanDuration(plan.duration_ms)} />}
                    </div>
                    {/* Honest progress bar from real counters */}
                    <div className="flex items-center gap-3">
                      <div className="h-1.5 w-40 overflow-hidden rounded-full bg-surface-2">
                        <div className="h-full rounded-full bg-accent" style={{ width: `${progressPct}%` }} />
                      </div>
                      <span className="mono-cell text-[10px] text-faint">
                        {doneCount}/{planned} tools terminal ({progressPct}%)
                      </span>
                    </div>
                    {(plan.started_at || plan.finished_at) && (
                      <p className="mt-2 text-[9.5px] text-faint">
                        started {plan.started_at ? formatDateTime(plan.started_at) : '—'} · finished{' '}
                        {plan.finished_at ? formatDateTime(plan.finished_at) : '—'}
                      </p>
                    )}
                    {plan.exists === false && (
                      <p className="mt-2 text-[9.5px] text-faint">
                        No persisted execution ledgger row yet — the plan below mirrors the configured task plan.
                      </p>
                    )}
                  </div>

                  {/* Stage-by-stage plan with concurrency */}
                  <div className="space-y-3">
                    {(plan.plan || []).map((g: any, gi: number) => {
                      const stageExs = exsByStage(g.stage);
                      const concurrency = maxConcurrency(stageExs);
                      return (
                        <div key={`${g.stage}-${gi}`} className="panel p-4">
                          <div className="flex flex-wrap items-center gap-2 mb-2">
                            <span className="mono-cell text-[11px] text-accent">{g.stage}</span>
                            <span className="mono-cell text-[9.5px] text-faint">{g.tools?.length ?? 0} plan gates</span>
                            {concurrency > 1 && (
                              <span className="mono-cell rounded-full border border-accent/40 bg-accent/5 px-2 py-0.5 text-[9.5px] text-accent">
                                ran up to {concurrency} in parallel
                              </span>
                            )}
                            {concurrency <= 1 && stageExs.length > 0 && (
                              <span className="mono-cell rounded-full border border-line px-2 py-0.5 text-[9.5px] text-faint">
                                serial
                              </span>
                            )}
                            <span className="ml-auto flex items-center gap-2">
                              {stageExs.length > 0 && (
                                <span className="mono-cell text-[9.5px] text-faint">{stageExs.length} execution row(s)</span>
                              )}
                            </span>
                          </div>
                          {(g.tools || []).length === 0 ? (
                            <p className="text-[10.5px] text-faint">No tools gated in this stage.</p>
                          ) : (
                            <div className="flex flex-wrap gap-1.5">
                              {(g.tools || []).map((tool: string) => {
                                const status = exStatusFor(g.stage, tool);
                                return (
                                  <span
                                    key={tool}
                                    className={`mono-cell inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[10px] ${
                                      status === 'completed'
                                        ? 'border-accent/40 text-accent bg-accent/5'
                                        : status === 'failed'
                                        ? 'border-critical/40 text-critical bg-critical/5'
                                        : status === 'skipped'
                                        ? 'border-line text-faint'
                                        : status
                                        ? 'border-warn/40 text-medium bg-warn/5'
                                        : 'border-line text-faint'
                                    }`}
                                    title={status ? `status: ${status}` : 'not yet executed'}
                                  >
                                    {tool}
                                    {status && <span className="opacity-70">/{status.replaceAll('_', ' ')}</span>}
                                  </span>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </div>
          )}

          {/* Executions ledger */}
          {tab === 'executions' && (
            <div className="panel p-4">
              <div className="flex items-center gap-1.5 mb-3">
                <Terminal className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                <h3 className="text-[12.5px] font-semibold text-text">Tool execution ledger ({executions.length})</h3>
                <span className="eyebrow ml-auto">real process telemetry</span>
              </div>
              {executions.length === 0 ? (
                <p className="text-[11px] text-faint">No tool executions recorded for this assessment.</p>
              ) : (
                <div className="space-y-1 max-h-[560px] overflow-y-auto">
                  {executions.map((ex) => (
                    <div key={ex.id} className="flex flex-wrap items-center gap-2 rounded-xl border border-line px-2.5 py-2">
                      <span className="mono-cell text-[10px] text-muted w-28 truncate shrink-0" title={ex.stage}>
                        {ex.stage}
                      </span>
                      <span className="mono-cell text-[11px] text-text w-32 truncate shrink-0" title={ex.tool}>
                        {ex.tool}
                      </span>
                      <span className="mono-cell text-[9.5px] text-faint shrink-0">{ex.adapter || '—'}</span>
                      <StatusBadge status={ex.status} />
                      {ex.attempt > 1 && <span className="mono-cell text-[9.5px] text-faint shrink-0">attempt {ex.attempt}</span>}
                      {ex.exit_code !== null && ex.exit_code !== undefined && (
                        <span className="mono-cell text-[9.5px] text-faint shrink-0">exit {ex.exit_code}</span>
                      )}
                      {ex.duration_ms != null && (
                        <span className="mono-cell text-[9.5px] text-faint shrink-0">{humanDuration(ex.duration_ms)}</span>
                      )}
                      <span className="mono-cell text-[9.5px] text-faint shrink-0">obs {ex.parsed_observations ?? 0}</span>
                      {ex.cancellation_state && (
                        <span className="mono-cell text-[9.5px] text-medium shrink-0">cancelled:{ex.cancellation_state}</span>
                      )}
                      {ex.termination_reason && (
                        <span className="text-[10px] text-faint truncate min-w-0" title={ex.termination_reason}>
                          {ex.termination_reason}
                        </span>
                      )}
                      {ex.started_at && (
                        <span className="mono-cell text-[9.5px] text-faint ml-auto shrink-0">{formatDateTime(ex.started_at)}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Observations with provenance */}
          {tab === 'observations' && (
            <div className="panel p-4">
              <div className="flex items-center gap-1.5 mb-3">
                <FileText className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                <h3 className="text-[12.5px] font-semibold text-text">Persisted observations ({observations.length})</h3>
                <span className="eyebrow ml-auto">evidence with tool provenance</span>
              </div>
              {observations.length === 0 ? (
                <p className="text-[11px] text-faint">No persisted observations for this assessment yet.</p>
              ) : (
                <div className="space-y-2 max-h-[560px] overflow-y-auto">
                  {observations.map((o) => (
                    <div key={o.id} className="rounded-xl border border-line px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="mono-cell text-[10px] text-accent">{o.kind}</span>
                        <span className="mono-cell text-[10px] text-faint">#{o.id}</span>
                        <span className="mono-cell text-[10px] text-muted">{o.tool}</span>
                        <span className="mono-cell text-[10px] text-faint">{o.status || 'recorded'}</span>
                        {o.asset_id && <span className="mono-cell text-[10px] text-faint">asset #{o.asset_id}</span>}
                        <span className="mono-cell text-[9.5px] text-faint ml-auto">{formatDateTime(o.created_at)}</span>
                      </div>
                      <p className="text-[11px] text-muted break-words" title={o.subject}>{o.subject}</p>
                      {o.provenance ? (
                        <div className="mt-2 rounded-lg border border-line bg-bg px-2.5 py-2">
                          <p className="eyebrow mb-1">Provenance — tool execution #{o.provenance.execution_id}</p>
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-0.5 text-[9.5px] text-faint">
                            <span>stage: {o.provenance.stage || '—'}</span>
                            <span>attempt: {o.provenance.attempt ?? 1}</span>
                            <StatusBadge status={o.provenance.status || 'unknown'} />
                            {o.provenance.exit_code !== null && o.provenance.exit_code !== undefined && (
                              <span>exit: {o.provenance.exit_code}</span>
                            )}
                            {o.provenance.duration_ms != null && <span>{humanDuration(o.provenance.duration_ms)}</span>}
                            <span>parsed obs: {o.provenance.parsed_observations ?? 0}</span>
                            {o.provenance.termination_reason && <span title={o.provenance.termination_reason}>{o.provenance.termination_reason}</span>}
                          </div>
                        </div>
                      ) : o.tool_execution_id ? (
                        <p className="mono-cell text-[9.5px] text-faint mt-2">tool execution #{o.tool_execution_id}</p>
                      ) : (
                        <p className="mono-cell text-[9.5px] text-faint mt-2">no tool-execution provenance (engine-native observation)</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Verification */}
          {tab === 'verification' && (
            <div className="panel p-4">
              <div className="flex items-center gap-1.5 mb-3">
                <ShieldCheck className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                <h3 className="text-[12.5px] font-semibold text-text">Finding verification ({findingRows.length})</h3>
                <span className="eyebrow ml-auto">deterministic — no auto re-probe</span>
              </div>

              {Object.keys(verificationCounts).length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 mb-3">
                  {Object.entries(verificationCounts).map(([state, count]) => (
                    <span key={state} className={`mono-cell rounded-full border px-2.5 py-0.5 text-[10px] ${VERIFICATION_TONES[state] || 'text-faint border-line'}`}>
                      {state}: {count}
                    </span>
                  ))}
                </div>
              )}

              {findingRows.length === 0 ? (
                <p className="text-[11px] text-faint">No findings to verify for this assessment.</p>
              ) : (
                <div className="space-y-2 max-h-[560px] overflow-y-auto">
                  {findingRows.map((f) => {
                    const isExpanded = expandedVuln === f.id;
                    const detail = findingDetails[f.id];
                    const verifications = detail?.verifications || [];
                    return (
                      <div key={f.id} className="overflow-hidden rounded-2xl border border-line">
                        <button
                          onClick={() => handleToggleVuln(f.id)}
                          className="w-full flex flex-wrap items-center gap-3 px-3 py-2.5 text-left hover:bg-surface-2/60 transition-colors cursor-pointer"
                          aria-expanded={isExpanded}
                        >
                          <SeverityBadge severity={f.severity} />
                          <span className="flex-1 min-w-0 text-[12px] font-medium text-text truncate">{f.title}</span>
                          <span className={`mono-cell shrink-0 rounded-full border px-2 py-0.5 text-[9.5px] ${VERIFICATION_TONES[(f.verification_state || 'unverified').toLowerCase()] || 'text-faint border-line'}`}>
                            {(f.verification_state || 'unverified').replaceAll('_', ' ')}
                          </span>
                          <span className={`mono-cell text-[10px] shrink-0 ${LIFECYCLE_TONES[f.status || 'confirmed'] || 'text-faint'}`}>
                            {(f.status || 'confirmed').toLowerCase()}
                          </span>
                          <ChevronRight
                            className={`w-3.5 h-3.5 text-faint shrink-0 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                            aria-hidden="true"
                          />
                        </button>
                        {isExpanded && (
                          <div className="border-t border-line bg-bg p-4 space-y-3">
                            <p className="text-[11.5px] text-muted leading-relaxed">{f.description || '—'}</p>
                            {detail?.verification_state && (
                              <p className="text-[10.5px] text-faint">
                                state: <span className="text-muted">{detail.verification_state}</span>
                              </p>
                            )}
                            {verifications.length === 0 ? (
                              <p className="text-[10.5px] text-faint">No verification checks recorded for this finding.</p>
                            ) : (
                              <div className="space-y-1.5">
                                <p className="eyebrow">Verification checks ({verifications.length})</p>
                                {verifications.map((v: any) => (
                                  <div key={v.id} className="rounded-xl border border-line px-3 py-2.5 text-[10.5px]">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className="mono-cell text-[10px] text-muted">{v.method}</span>
                                      <StatusBadge status={v.status} />
                                      {v.rule_id && <span className="mono-cell text-[9.5px] text-faint">{v.rule_id}</span>}
                                      {(v.observation_ids || []).length > 0 && (
                                        <span className="mono-cell text-[9.5px] text-faint">
                                          observations: {v.observation_ids.map((o: number) => `#${o}`).join(', ')}
                                        </span>
                                      )}
                                      {v.completed_at && (
                                        <span className="mono-cell text-[9.5px] text-faint ml-auto">{formatDateTime(v.completed_at)}</span>
                                      )}
                                    </div>
                                    {v.condition && <p className="mono-cell text-[9.5px] text-faint mt-1">condition: {v.condition}</p>}
                                    {v.reason && <p className="text-[10px] text-muted mt-1">{v.reason}</p>}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Console */}
          {tab === 'console' && (
            <div className="space-y-4">
              <div className="flex items-center justify-end gap-1">
                <span className="eyebrow mr-1">Console</span>
                <button
                  onClick={() => setConsoleMode('classic')}
                  className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[9.5px] transition-colors duration-500 ease-spring ${
                    consoleMode === 'classic' ? 'border-accent/60 text-accent bg-accent/10' : 'border-line text-faint hover:text-muted'
                  }`}
                >
                  Classic
                </button>
                <button
                  onClick={() => setConsoleMode('phase7')}
                  className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[9.5px] transition-colors duration-500 ease-spring ${
                    consoleMode === 'phase7' ? 'border-accent/60 text-accent bg-accent/10' : 'border-line text-faint hover:text-muted'
                  }`}
                >
                  Phase 7
                </button>
              </div>
              {consoleMode === 'phase7' ? (
                <Phase7Console scanId={scan.id} />
              ) : (
                <div className="panel p-4">
                  <div className="flex items-center gap-1.5 mb-2">
                    <Terminal className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                    <span className="text-[12.5px] font-semibold text-text">Live events</span>
                  </div>
                  <pre className="max-h-80 overflow-y-auto whitespace-pre-wrap rounded-xl border border-line bg-bg p-3 font-mono text-[10.5px] leading-relaxed text-accent/90">
                    {liveEvents.length === 0 ? '// waiting…' : liveEvents.join('\n')}
                  </pre>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};

const DimensionCard: React.FC<{ label: string; dim?: any }> = ({ label, dim }) => {
  const distinct: any[] = dim?.distinct || [];
  const shown = distinct.slice(0, 8);
  const more = distinct.length - shown.length;
  const singular = label.toLowerCase() === 'ports' ? 'port' : label.toLowerCase() === 'urls' ? 'url' : 'host';
  return (
    <div className="rounded-xl border border-line px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11.5px] font-medium text-text">{label}</span>
        <span className="mono-cell flex items-center gap-1.5 text-[10px] text-faint">
          <Boxes className="w-3 h-3" aria-hidden="true" />
          {dim?.observed ?? 0} observed
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {shown.length === 0 ? (
          <span className="mono-cell text-[9.5px] text-faint">no {singular}s observed</span>
        ) : (
          shown.map((v: any) => (
            <span key={String(v)} className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9.5px] text-muted" title={String(v)}>
              {String(v)}
            </span>
          ))
        )}
        {more > 0 && <span className="mono-cell text-[9.5px] text-faint">+{more} more</span>}
      </div>
      {(dim?.tools || []).length > 0 && (
        <p className="mono-cell text-[9px] text-faint mt-1.5">captured by: {dim.tools.join(', ')}</p>
      )}
    </div>
  );
};

const KV: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div>
    <p className="eyebrow mb-0.5">{label}</p>
    <p className={`text-[11px] text-muted break-words ${mono ? 'font-mono' : ''}`}>{value}</p>
  </div>
);

export default ScanDetail;