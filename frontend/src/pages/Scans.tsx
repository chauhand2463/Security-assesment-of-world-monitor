import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  Layers,
  Terminal,
  Scale,
  FileSearch,
  ShieldCheck,
  ChevronRight,
  RotateCw,
  FileDown,
  Activity,
  FileText,
  Boxes,
  GitBranch,
  ExternalLink,
} from 'lucide-react';
import { apiFetch, authUrl } from '../api';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { SkeletonPanel } from '../components/Skeleton';
import { formatDate, formatDateTime } from '../components/format';
import { Phase7Console } from '../components/Phase7Console';

const STAGES = [
  { id: 'queued', label: 'Queued' },
  { id: 'starting', label: 'Starting' },
  { id: 'recon', label: 'Recon' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'service_scan', label: 'Service Scan' },
  { id: 'http_scan', label: 'HTTP Scan' },
  { id: 'vulnerability_scan', label: 'Vulnerability Scan' },
  { id: 'analysis', label: 'Analysis' },
  { id: 'reporting', label: 'Reporting' },
];

const LIFECYCLE_STATUSES = [
  'confirmed',
  'candidate',
  'validated',
  'rejected',
  'duplicate',
  'accepted',
  'remediated',
  'reopened',
];

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

const dedupeTools = (rows: any[]): any[] => {
  const order: string[] = [];
  const byName = new Map<string, any>();
  rows.forEach((row) => {
    if (!byName.has(row.name)) order.push(row.name);
    byName.set(row.name, row);
  });
  return order.map((name) => byName.get(name));
};

export const Scans: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<any | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [tools, setTools] = useState<any[]>([]);
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [liveEvents, setLiveEvents] = useState<string[]>([]);
  const [assessmentSummary, setAssessmentSummary] = useState<any | null>(null);
  const [findingStatusFilter, setFindingStatusFilter] = useState<string>('all');
  const [findingDetails, setFindingDetails] = useState<Record<number, any>>({});
  const [reportExport, setReportExport] = useState<{ markdown: string; hash: string; generated_at: string } | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [consoleMode, setConsoleMode] = useState<'classic' | 'phase7'>('classic');
  const [workspaceTab, setWorkspaceTab] = useState<'overview' | 'console' | 'observations' | 'findings' | 'assets'>('overview');
  const [observations, setObservations] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);
  const liveRef = useRef<HTMLDivElement>(null);

  const TAB_ITEMS: { id: typeof workspaceTab; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <Activity className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'console', label: 'Live Console', icon: <Terminal className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'observations', label: `Observations`, icon: <FileText className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'findings', label: `Findings`, icon: <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" /> },
    { id: 'assets', label: 'Assets', icon: <Boxes className="w-3.5 h-3.5" aria-hidden="true" /> },
  ];

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/scans/list');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
      }
    } catch (err) {
      console.error('Error fetching scans list:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectScan = async (id: number) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setLiveEvents([]);
    setDetailsLoading(true);
    setDetailError('');
    setFindingStatusFilter('all');
    setFindingDetails({});
    setAssessmentSummary(null);
    setReportExport(null);
    setObservations([]);
    setAssets([]);
    try {
      const res = await apiFetch(`/scans/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedScan(data);
        setVulnerabilities(data.vulnerabilities || []);
        setTools(dedupeTools(data.tools || []));
        setLogs(data.logs || '');
        startSSEStream(id);
      } else {
        const errData = await res.json().catch(() => null);
        setDetailError(errData?.detail || 'Failed to load scan details.');
      }
    } catch {
      setDetailError('Server connection failed.');
    } finally {
      setDetailsLoading(false);
    }
    try {
      const res = await apiFetch(`/scans/${id}/assessment`);
      if (res.ok) setAssessmentSummary(await res.json());
    } catch (err) {
      console.error('Error fetching assessment summary:', err);
    }
    try {
      const res = await apiFetch(`/scans/${id}/observations`);
      if (res.ok) {
        const data = await res.json();
        setObservations(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error('Error fetching observations:', err);
    }
    try {
      const res = await apiFetch(`/scans/${id}/assets`);
      if (res.ok) {
        const data = await res.json();
        setAssets(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error('Error fetching assets:', err);
    }
  };

  const loadFindingDetail = async (id: number) => {
    if (findingDetails[id]) return;
    try {
      const res = await apiFetch(`/findings/${id}`);
      if (res.ok) {
        const data = await res.json();
        setFindingDetails((prev) => ({ ...prev, [id]: data }));
      }
    } catch (err) {
      console.error('Error fetching finding detail:', err);
    }
  };

  const handleToggleVuln = (id: number) => {
    const next = expandedVuln === id ? null : id;
    setExpandedVuln(next);
    if (next !== null) loadFindingDetail(id);
  };

  const handleExportReport = async () => {
    if (!selectedScan) return;
    setReportLoading(true);
    try {
      const res = await apiFetch(`/scans/${selectedScan.id}/report?format=markdown`);
      if (res.ok) {
        const data = await res.json();
        setReportExport({
          markdown: data.report || '',
          hash: data.content_hash || '',
          generated_at: data.generated_at || '',
        });
      } else {
        setLiveEvents((prev) => [...prev, '[Error] Report export failed.']);
      }
    } catch {
      setLiveEvents((prev) => [...prev, '[Error] Report export failed: server unreachable.']);
    } finally {
      setReportLoading(false);
    }
  };

  const startSSEStream = (id: number) => {
    const es = new EventSource(authUrl(`/scans/${id}/events`));
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'error') {
          setLiveEvents((prev) => [...prev, `[Error] ${data.error}`]);
          setDetailsLoading(false);
          return;
        }
        if (data.type === 'stage') {
          setSelectedScan((prev: any) => (prev ? { ...prev, stage: data.stage, status: data.status } : prev));
          setLiveEvents((prev) => [...prev, `[Stage] ${data.stage} (${data.status})`]);
        }
        if (data.type === 'tool') {
          const line = `[Tool] ${data.tool} -> ${data.status}`;
          setLiveEvents((prev) => [...prev, line]);
          setTools((prev) => {
            const idx = prev.findIndex((t) => t.name === data.tool);
            if (idx === -1) return [...prev, { name: data.tool, status: data.status }];
            const next = prev.slice();
            next[idx] = { ...next[idx], status: data.status };
            return next;
          });
        }
        if (data.type === 'finding') {
          setLiveEvents((prev) => [...prev, `[Finding] ${data.severity}: ${data.title}`]);
        }
        if (data.type === 'progress') {
          setSelectedScan((prev: any) =>
            prev ? { ...prev, coverage: data.coverage, security_score: data.security_score } : prev
          );
        }
        if (data.type === 'done') {
          setSelectedScan((prev: any) =>
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
          setDetailsLoading(false);
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
    fetchScans();
    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, []);

  useEffect(() => {
    const wanted = searchParams.get('scan');
    if (wanted && scans.length > 0 && !selectedScan) {
      const match = scans.find((s) => String(s.id) === wanted);
      if (match) handleSelectScan(match.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, scans, selectedScan]);

  useEffect(() => {
    if (liveRef.current) liveRef.current.scrollTop = liveRef.current.scrollHeight;
  }, [liveEvents]);

  const handleCancel = async () => {
    if (!selectedScan) return;
    setCancelling(true);
    try {
      const res = await apiFetch(`/scans/${selectedScan.id}/cancel`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setLiveEvents((prev) => [...prev, `[System] Cancellation requested. ${data.message || ''}`]);
        setSelectedScan((prev: any) => (prev ? { ...prev, status: 'Cancelling…' } : prev));
      } else {
        const errData = await res.json().catch(() => null);
        setLiveEvents((prev) => [...prev, `[Error] Cancel failed: ${errData?.detail || 'unknown'}`]);
      }
    } catch {
      setLiveEvents((prev) => [...prev, '[Error] Cancel failed: server unreachable.']);
    } finally {
      setCancelling(false);
    }
  };

  const stageIdx = (s?: string) => STAGES.findIndex((st) => st.id === (s || '').toLowerCase());
  const currentStageIdx = selectedScan ? stageIdx(selectedScan.stage) : -1;
  const terminalStage = selectedScan
    ? ['completed', 'partial', 'failed', 'cancelled'].includes((selectedScan.stage || '').toLowerCase())
    : false;
  const lastInclusive = terminalStage ? STAGES.length : currentStageIdx + 1;
  const isActive = (idx: number) => !terminalStage && idx === currentStageIdx;
  const isDone = (idx: number) => idx < lastInclusive;
  const notInstalledTools = tools.filter((t) => (t.status || '').toLowerCase() === 'not installed').length;
  const filteredVulnerabilities =
    findingStatusFilter === 'all'
      ? vulnerabilities
      : vulnerabilities.filter((v) => (v.status || 'confirmed').toLowerCase() === findingStatusFilter);
  const canCancel =
    selectedScan &&
    (selectedScan.status === 'Running' || selectedScan.status === 'Pending' || selectedScan.status === 'Cancelling…') &&
    !['completed', 'partial', 'failed', 'cancelled'].includes((selectedScan.stage || '').toLowerCase());
  const sih = selectedScan?.assessment?.sih as
    | { areas: any[]; unmapped_categories?: Record<string, number> }
    | undefined;
  const SIH_TONES: Record<string, string> = {
    covered: 'text-accent border-accent/40 bg-accent/5',
    partial: 'text-medium border-warn/40 bg-warn/5',
    not_assessed: 'text-faint border-line',
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Assessments"
        title="Assessments"
        description="Stage-driven lifetime of each assessment, its evidence, and outcomes."
        actions={
          selectedScan && currentStageIdx >= 0 && !terminalStage ? (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-critical/35 px-3 py-1.5 text-[11.5px] text-critical transition-colors duration-500 ease-spring hover:bg-critical/[0.08] disabled:opacity-50"
            >
              <Scale className="w-3 h-3" aria-hidden="true" />
              {cancelling ? 'Requesting…' : 'Request cancellation'}
            </button>
          ) : (
            <button
              onClick={fetchScans}
              className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
            >
              <RotateCw className="w-3 h-3" aria-hidden="true" />
              Refresh
            </button>
          )
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Scan list */}
        <div className="lg:col-span-1">
          <div className="panel overflow-hidden">
            <div className="px-4 pt-4 pb-2 flex items-center justify-between">
              <h2 className="text-[12.5px] font-semibold text-text">Assessment runs</h2>
              <span className="mono-cell text-[10px] text-faint">{scans.length}</span>
            </div>
            <div className="max-h-[70vh] overflow-y-auto p-2">
              {loading ? (
                <div className="px-2 space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="skeleton h-14 rounded-xl" />
                  ))}
                </div>
              ) : scans.length === 0 ? (
                <EmptyState
                  title="No assessments"
                  description="Queue an assessment from the New Assessment page."
                />
              ) : (
                <ul className="space-y-1">
                  {scans.map((scan) => {
                    const selected = selectedScan?.id === scan.id;
                    return (
                      <li key={scan.id}>
                        <button
                          onClick={() => handleSelectScan(scan.id)}
                          className={`w-full cursor-pointer rounded-xl border-l-2 px-3 py-2.5 text-left transition-colors duration-500 ease-spring ${
                            selected
                              ? 'bg-surface-2 border-accent'
                              : 'border-transparent hover:bg-surface-2/60'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[12px] font-medium text-text truncate">{scan.target}</span>
                            <StatusBadge status={scan.status} />
                          </div>
                          <div className="flex items-center justify-between mt-1 text-[10px] text-faint">
                            <span>#{scan.id}</span>
                            <span>{formatDate(scan.created_at)}</span>
                          </div>
                          {scan.security_score !== null && (
                            <p className="mono-cell text-[10px] text-faint mt-0.5">score: {scan.security_score}/100</p>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* Detail */}
        <div className="lg:col-span-3">
          <div className="space-y-4">
            {detailsLoading ? (
              <SkeletonPanel className="min-h-[360px]" />
            ) : detailError ? (
              <ErrorState message={detailError} onRetry={() => selectedScan && handleSelectScan(selectedScan.id)} />
            ) : !selectedScan ? (
              <EmptyState
                icon={<FileSearch className="w-4 h-4" aria-hidden="true" />}
                title="No assessment selected"
                description="Select an assessment from the list to inspect its pipeline, evidence, and findings."
              />
            ) : (
              <>
                {/* Header summary */}
                <div className="panel p-4">
                  <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                    <div className="min-w-0">
                      <h2 className="text-base font-semibold text-text truncate">{selectedScan.target}</h2>
                      <p className="mono-cell text-[10.5px] text-faint mt-1">
                        #{selectedScan.id} · queued {formatDateTime(selectedScan.created_at)}
                      </p>
                      <div className="flex flex-wrap items-center gap-2 mt-2">
                        <StatusBadge status={selectedScan.status} />
                        <span className="mono-cell text-[10px] text-faint">stage: {selectedScan.stage || 'queued'}</span>
                        <span className="mono-cell text-[10px] text-faint">
                          mode: {selectedScan.simulation ? 'simulation' : 'real'}
                        </span>
                      </div>
                    </div>
                    <div className="shrink-0 flex items-center gap-6">
                      <div className="text-right">
                        <p className="eyebrow">Coverage</p>
                        <p className="text-lg font-semibold text-text">
                          {selectedScan.coverage !== null && selectedScan.coverage !== undefined
                            ? `${selectedScan.coverage}%`
                            : '—'}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="eyebrow">Security score</p>
                        <p className="text-lg font-semibold text-text">
                          {selectedScan.security_score !== null && selectedScan.security_score !== undefined
                            ? `${selectedScan.security_score}/100`
                            : '—'}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="mt-3 flex items-center gap-2">
                    <Link
                      to={`/scans/${selectedScan.id}`}
                      className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3 py-1.5 text-[11px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20"
                    >
                      <ExternalLink className="w-3 h-3" aria-hidden="true" />
                      Open full detail
                    </Link>
                    <span className="text-[10px] text-faint">execution plan · ledger · verification</span>
                  </div>

                  {/* Lifecycle */}
                  {selectedScan.stage && (
                    <div className="mt-4 pt-4 border-t border-line">
                      <div className="flex items-center justify-between gap-2 mb-2.5">
                        <div className="flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                          <span className="text-[12.5px] font-semibold text-text">Pipeline lifecycle</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <span className="eyebrow mr-1">Console</span>
                          <button
                            onClick={() => setConsoleMode('classic')}
                            className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[9.5px] transition-colors duration-500 ease-spring ${
                              consoleMode === 'classic'
                                ? 'border-accent/60 text-accent bg-accent/10'
                                : 'border-line text-faint hover:text-muted'
                            }`}
                          >
                            Classic
                          </button>
                          <button
                            onClick={() => setConsoleMode('phase7')}
                            className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[9.5px] transition-colors duration-500 ease-spring ${
                              consoleMode === 'phase7'
                                ? 'border-accent/60 text-accent bg-accent/10'
                                : 'border-line text-faint hover:text-muted'
                            }`}
                          >
                            Phase 7
                          </button>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
                        {STAGES.map((st, idx) => {
                          const done = isDone(idx) || (terminalStage && isDone(idx));
                          const active = isActive(idx);
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
                              {idx < STAGES.length - 1 && (
                                <span className={`w-2 h-px ${isDone(idx) ? 'bg-line-strong' : 'bg-line'}`} />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>

                {/* Workspace tab bar */}
                <div className="flex items-center gap-1 overflow-x-auto border-b border-line -mb-px">
                  {TAB_ITEMS.map((tab) => {
                    const active = workspaceTab === tab.id;
                    const count =
                      tab.id === 'findings'
                        ? vulnerabilities.length
                        : tab.id === 'observations'
                        ? observations.length
                        : tab.id === 'assets'
                        ? assets.length
                        : null;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setWorkspaceTab(tab.id)}
                        className={`inline-flex cursor-pointer items-center gap-1.5 rounded-t-lg border-b-2 px-3 py-2 text-[11.5px] transition-colors duration-500 ease-spring ${
                          active
                            ? 'border-accent text-text'
                            : 'border-transparent text-faint hover:text-muted'
                        }`}
                        aria-selected={active}
                      >
                        {tab.icon}
                        {tab.label}
                        {count !== null && count > 0 && (
                          <span className="mono-cell rounded-full border border-line px-1.5 text-[9px]">{count}</span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* SIH26163 security-area coverage */}
                {workspaceTab === 'overview' && sih?.areas?.length ? (
                  <div className="panel p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-[12.5px] font-semibold text-text">SIH26163 security-area coverage</h3>
                      <span className="eyebrow">{sih.areas.filter((a) => a.executed > 0).length}/7 areas exercised</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {sih.areas.map((a) => (
                        <div key={a.key} className="rounded-xl border border-line px-3 py-2.5">
                          <div className="flex items-start justify-between gap-2">
                            <span className="text-[11.5px] font-medium text-text">{a.title}</span>
                            <span
                              className={`mono-cell shrink-0 rounded-full border px-2 py-0.5 text-[9px] uppercase tracking-wide ${
                                SIH_TONES[a.status] || 'text-faint border-line'
                              }`}
                            >
                              {a.status.replace('_', ' ')}
                            </span>
                          </div>
                          <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-surface-2">
                            {a.coverage_percent !== null ? (
                              <div
                                className={`h-full rounded-full ${a.status === 'covered' ? 'bg-accent' : 'bg-warn'}`}
                                style={{ width: `${Math.min(100, a.coverage_percent)}%` }}
                              />
                            ) : null}
                          </div>
                          <div className="mt-1.5 flex items-center justify-between mono-cell text-[9.5px] text-faint">
                            <span>
                              {a.executed}/{a.applicable} applicable tests executed
                            </span>
                            <span>{a.coverage_percent !== null ? `${a.coverage_percent}%` : 'not assessed'}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                    {sih.unmapped_categories && Object.keys(sih.unmapped_categories).length > 0 && (
                      <p className="mt-3 text-[10px] text-faint">
                        Categories outside the SIH framework: {Object.keys(sih.unmapped_categories).join(', ')}
                      </p>
                    )}
                  </div>
                ) : null}

                {/* Overview tab: Phase 6 assessment + tool pipeline */}
                {workspaceTab === 'overview' && (
                <>
                {selectedScan.assessment?.coverage && (
                  <div className="panel p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-[12.5px] font-semibold text-text">Assessment coverage</h3>
                      <span className="eyebrow">
                        {selectedScan.assessment.coverage.findings_confirmed ?? 0} confirmed finding(s)
                      </span>
                    </div>

                    {assessmentSummary?.headline && (
                      <div
                        className={`mb-3 rounded-xl border px-3.5 py-2.5 text-[11.5px] leading-relaxed ${
                          assessmentSummary.assessment_status === 'completed'
                            ? 'border-accent/30 bg-accent/5 text-accent'
                            : 'border-warn/30 bg-warn/5 text-medium'
                        }`}
                      >
                        {assessmentSummary.headline}
                      </div>
                    )}

                    {(assessmentSummary || assessmentSummary?.aggregate) && (
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
                        <KV
                          label="Assessment status"
                          value={assessmentSummary.assessment_status?.replaceAll('_', ' ') || '—'}
                          mono
                        />
                        <KV label="Completeness" value={assessmentSummary.assessment_completeness || '—'} mono />
                        <KV
                          label="Tests executed"
                          value={`${selectedScan.assessment.coverage.tests_executed ?? 0}/${selectedScan.assessment.coverage.tests_applicable ?? 0}`}
                          mono
                        />
                        <KV label="Observed findings" value={String(selectedScan.assessment.coverage.observations ?? 0)} mono />
                      </div>
                    )}

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
                      <KV label="Coverage" value={`${selectedScan.assessment.coverage.coverage_percent ?? '—'}%`} mono />
                      <KV label="Not applicable" value={String(selectedScan.assessment.coverage.tests_not_applicable ?? 0)} mono />
                      <KV label="Failed" value={String(selectedScan.assessment.coverage.tests_failed ?? 0)} mono />
                      <KV label="Skipped" value={String(selectedScan.assessment.coverage.tests_skipped ?? 0)} mono />
                    </div>

                    {assessmentSummary?.aggregate && (
                      <div className="flex flex-wrap items-center gap-1.5 mb-3">
                        {Object.entries(assessmentSummary.aggregate.by_status || {}).map(
                          ([status, count]) =>
                            (count as number) > 0 && (
                              <span
                                key={status}
                                className={`mono-cell text-[10px] border border-line rounded-md px-2 py-0.5 ${
                                  LIFECYCLE_TONES[status] || 'text-faint'
                                }`}
                              >
                                {status}: {count as number}
                              </span>
                            )
                        )}
                      </div>
                    )}

                    {selectedScan.assessment.coverage.findings_confirmed === 0 && (
                      <p className="text-[10.5px] text-faint mb-2">
                        Zero confirmed findings is not the same as zero risk. Unevaluated areas are listed below.
                      </p>
                    )}

                    {(assessmentSummary?.snapshot?.configuration?.tools_missing?.length ?? 0) > 0 && (
                      <div className="mb-3 rounded-xl border border-warn/30 bg-warn/[0.06] px-3 py-2.5">
                        <p className="eyebrow mb-1">Assessment gaps — tools not installed</p>
                        <div className="flex flex-wrap gap-1.5">
                          {(assessmentSummary.snapshot.configuration.tools_missing as string[]).map((t) => (
                            <span key={t} className="mono-cell text-[10px] text-medium">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {assessmentSummary?.snapshot?.configuration && (
                      <div className="flex flex-wrap gap-x-4 gap-y-1 mb-3 text-[10px] text-faint">
                        <span>active testing: {assessmentSummary.snapshot.configuration.active_testing ? 'on' : 'off'}</span>
                        <span>engine: {assessmentSummary.snapshot.configuration.assessment_engine ? 'on' : 'off'}</span>
                        <span>jwt: {assessmentSummary.snapshot.configuration.jwt_tokens_configured ? 'configured' : 'none'}</span>
                        <span>ssrf: {assessmentSummary.snapshot.configuration.ssrf_validation_configured ? 'configured' : 'none'}</span>
                        <span>config hash: {assessmentSummary.snapshot.config_fingerprint?.slice(0, 12)}</span>
                      </div>
                    )}

                    {selectedScan.assessment.tests?.length > 0 && (
                      <div className="space-y-1 max-h-52 overflow-y-auto">
                        {selectedScan.assessment.tests.map((t: any) => (
                          <div key={t.test_id} className="flex items-center gap-2 rounded-lg border border-line px-2.5 py-1.5">
                            <span className="mono-cell text-[10px] text-muted w-44 truncate">{t.test_id}</span>
                            <span
                              className={`mono-cell text-[9.5px] uppercase shrink-0 ${
                                t.status === 'executed' ? 'text-accent' : t.status === 'failed' ? 'text-high' : 'text-faint'
                              }`}
                            >
                              {t.status}
                            </span>
                            <span className="flex-1 min-w-0 text-[10px] text-faint truncate" title={t.reason || ''}>
                              {t.reason || ''}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="mt-3 pt-3 border-t border-line">
                      <button
                        onClick={handleExportReport}
                        disabled={reportLoading}
                        className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text disabled:opacity-50"
                      >
                        <FileDown className="w-3 h-3" aria-hidden="true" />
                        {reportLoading ? 'Building export…' : reportExport ? 'Rebuild markdown export' : 'Export report (markdown)'}
                      </button>
                      {reportExport && (
                        <div className="mt-3">
                          <div className="flex flex-wrap gap-x-4 gap-y-1 mb-2 text-[10px] text-faint">
                            <span className="mono-cell">sha256: {reportExport.hash.slice(0, 16)}…</span>
                            <span>{reportExport.generated_at}</span>
                          </div>
                          <pre className="max-h-96 overflow-y-auto whitespace-pre-wrap rounded-xl border border-line bg-bg p-3 font-mono text-[10px] leading-relaxed text-accent/90">
                            {reportExport.markdown}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Tool pipeline */}
                <div className="panel p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-[12.5px] font-semibold text-text">Tool pipeline ({tools.length})</h3>
                    {notInstalledTools > 0 && (
                      <span className="mono-cell text-[10px] text-medium">{notInstalledTools} not installed</span>
                    )}
                  </div>
                  {tools.length === 0 ? (
                    <p className="text-[11px] text-faint">No tool completions yet. Queued jobs launch asynchronously.</p>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                      {tools.map((tr, i) => (
                        <div
                          key={`${tr.name}-${i}`}
                          className="flex items-center justify-between gap-2 rounded-xl border border-line px-2.5 py-2"
                          title={tr.raw_output ? 'raw output available in observations' : undefined}
                        >
                          <span className="mono-cell text-[11px] text-text truncate">{tr.name}</span>
                          <StatusBadge status={tr.status} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                </>
                )}

                {/* Observations tab */}
                {workspaceTab === 'observations' && (
                  <div className="panel p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-[12.5px] font-semibold text-text">Observations ({observations.length})</h3>
                      <span className="eyebrow">persisted evidence</span>
                    </div>
                    {observations.length === 0 ? (
                      <p className="text-[11px] text-faint">No persisted observations for this assessment yet.</p>
                    ) : (
                      <div className="space-y-2 max-h-[540px] overflow-y-auto">
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
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Findings tab */}
                {workspaceTab === 'findings' && (
                <div className="panel p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-[12.5px] font-semibold text-text">
                      Findings ({vulnerabilities.length})
                    </h3>
                    <span className="eyebrow">evidence-backed</span>
                  </div>

                  {vulnerabilities.length === 0 ? (
                    <div className="flex flex-col items-center text-center py-6">
                      <ShieldCheck className="w-8 h-8 text-faint" strokeWidth={1.5} aria-hidden="true" />
                      <p className="text-[12px] text-muted mt-2">No evidence-backed findings persisted for this assessment.</p>
                      <p className="text-[10.5px] text-faint mt-1">Findings are only ever created from real tool observations.</p>
                    </div>
                  ) : (
                    <>
                      <div className="flex flex-wrap items-center gap-1.5 mb-3">
                        <button
                          onClick={() => setFindingStatusFilter('all')}
                              className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[10px] transition-colors duration-500 ease-spring ${
                            findingStatusFilter === 'all'
                              ? 'border-accent/60 text-accent bg-accent/10'
                              : 'border-line text-faint hover:text-muted'
                          }`}
                        >
                          all
                        </button>
                        {LIFECYCLE_STATUSES.map((status) => {
                          const count = vulnerabilities.filter(
                            (v) => (v.status || 'confirmed').toLowerCase() === status
                          ).length;
                          if (count === 0) return null;
                          const active = findingStatusFilter === status;
                          return (
                            <button
                              key={status}
                              onClick={() => setFindingStatusFilter(active ? 'all' : status)}
                          className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[10px] transition-colors duration-500 ease-spring ${
                                active
                                  ? 'border-accent/60 bg-accent/10 ' + (LIFECYCLE_TONES[status] || 'text-accent')
                                  : 'border-line text-faint hover:text-muted'
                              }`}
                            >
                              {status}: {count}
                            </button>
                          );
                        })}
                      </div>

                      <div className="space-y-2">
                        {filteredVulnerabilities.map((vuln) => {
                          const isExpanded = expandedVuln === vuln.id;
                          return (
                            <div key={vuln.id} className="overflow-hidden rounded-2xl border border-line">
                              <button
                                onClick={() => handleToggleVuln(vuln.id)}
                                className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-surface-2/60 transition-colors cursor-pointer"
                                aria-expanded={isExpanded}
                              >
                                <SeverityBadge severity={vuln.severity} />
                                <span className="flex-1 min-w-0 text-[12px] font-medium text-text truncate">{vuln.title}</span>
                                <span className={`mono-cell text-[10px] shrink-0 ${LIFECYCLE_TONES[vuln.status || 'confirmed'] || 'text-faint'}`}>
                                  {(vuln.status || 'confirmed').toLowerCase()}
                                </span>
                                {vuln.cve && <span className="mono-cell text-[10px] text-faint shrink-0">{vuln.cve}</span>}
                                <ChevronRight
                                  className={`w-3.5 h-3.5 text-faint shrink-0 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                                  aria-hidden="true"
                                />
                              </button>

                              {isExpanded && <FindingDetail vuln={vuln} detail={findingDetails[vuln.id]} />}
                            </div>
                          );
                        })}
                      </div>
                    </>
                  )}
                </div>
                )}

                {/* Live Console tab */}
                {workspaceTab === 'console' && (
                  <>
                    {(liveEvents.length > 0 || logs) && (
                      <>
                        <div className="panel p-4">
                          <div className="flex items-center gap-1.5 mb-2">
                            <Terminal className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                            <span className="text-[12.5px] font-semibold text-text">Live events</span>
                          </div>
                          <pre className="max-h-28 overflow-y-auto whitespace-pre-wrap rounded-xl border border-line bg-bg p-3 font-mono text-[10.5px] leading-relaxed text-accent/90">
                            {liveEvents.length === 0 ? '// waiting…' : liveEvents.join('\n')}
                          </pre>
                        </div>
                        <div className="panel p-4">
                          <div className="flex items-center gap-1.5 mb-2">
                            <Terminal className="w-3.5 h-3.5 text-faint" aria-hidden="true" />
                            <span className="text-[12.5px] font-semibold text-text">Execution logs</span>
                          </div>
                          <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap rounded-xl border border-line bg-bg p-3 font-mono text-[10.5px] leading-relaxed text-muted">
                            {logs || '// No logs yet.'}
                          </pre>
                        </div>
                      </>
                    )}
                    {consoleMode === 'phase7'
                      ? <Phase7Console scanId={selectedScan.id} />
                      : liveEvents.length === 0 && !logs
                      ? <p className="text-[11px] text-faint">No console activity yet for this assessment.</p>
                      : null}
                  </>
                )}

                {/* Assets tab */}
                {workspaceTab === 'assets' && (
                  <div className="panel p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-[12.5px] font-semibold text-text">Asset graph ({assets.length})</h3>
                      <span className="eyebrow mb-1">built from persisted observations</span>
                    </div>
                    {assets.length === 0 ? (
                      <p className="text-[11px] text-faint">No assets surfaced for this assessment yet.</p>
                    ) : (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-[540px] overflow-y-auto">
                        {assets.map((a) => (
                          <div key={a.id} className="rounded-xl border border-line px-3 py-2.5">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="mono-cell text-[10px] text-accent">{a.type}</span>
                              <span className="font-mono text-[11px] text-text break-all">{a.value}</span>
                              <span className="mono-cell text-[9.5px] text-faint ml-auto">#{a.id}</span>
                            </div>
                            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[9.5px] text-faint">
                              {a.source && <span>source: {a.source}</span>}
                              {a.parent_asset_id && <span>parent: #{a.parent_asset_id}</span>}
                              {a.children?.length > 0 && (
                                <span>children: {a.children.map((c: number) => `#${c}`).join(', ')}</span>
                              )}
                              <span>{formatDate(a.created_at)}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const FindingDetail: React.FC<{ vuln: any; detail?: any }> = ({ vuln, detail }) => {
  const d = detail || vuln;
  const cvss = d.cvss || {};
  const cvssConsistency = cvss.consistency || {};
  const impactDetails = d.impact_details || {};
  const remediationDetails = d.remediation_details || {};

  return (
    <div className="border-t border-line bg-bg p-4 text-[11.5px] space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KV label="State" value={d.state || 'NEW'} mono />
        <KV
          label="Lifecycle"
          value={(d.status || 'confirmed').toLowerCase()}
          mono
        />
        <KV label="Component" value={d.affected_component || '—'} mono />
        <KV label="Parameter" value={d.parameter || '—'} mono />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KV label="OWASP" value={d.owasp || '—'} />
        <KV label="MITRE ATT&CK" value={d.mitre || '—'} />
        <KV label="CWE" value={d.cwe ? `CWE-${d.cwe}` : '—'} mono />
        <KV label="Rule" value={d.rule_id || '—'} mono />
      </div>

      {(cvss.vector || cvss.score !== undefined || vuln.cvss != null) && (
        <div>
          <p className="eyebrow mb-1.5">CVSS</p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KV
              label="Score / version"
              value={cvss.score !== undefined ? `${cvss.score}${cvss.version ? ` (v${cvss.version})` : ''}` : vuln.cvss != null ? String(vuln.cvss) : '—'}
              mono
            />
            <KV label="Vector" value={cvss.vector || '—'} mono />
            <KV
              label="Consistency"
              value={cvssConsistency.status !== undefined ? cvssConsistency.status : '—'}
              mono
            />
            <KV label="Note" value={cvssConsistency.note || '—'} />
          </div>
        </div>
      )}

      <div>
        <p className="eyebrow mb-1">Description</p>
        <p className="text-muted leading-relaxed">{d.description}</p>
      </div>

      {d.remediation && (
        <div>
          <p className="eyebrow mb-1">Recommended mitigation</p>
          <p className="text-accent leading-relaxed">{d.remediation}</p>
        </div>
      )}

      {remediationDetails?.summary && (
        <div>
          <p className="eyebrow mb-1">Remediation details</p>
          <p className="text-muted leading-relaxed">{remediationDetails.summary}</p>
          {remediationDetails.technical_fix && (
            <p className="text-muted leading-relaxed mt-1">{remediationDetails.technical_fix}</p>
          )}
          {remediationDetails.validation_steps && (
            <p className="text-faint leading-relaxed mt-1">{remediationDetails.validation_steps}</p>
          )}
        </div>
      )}

      {(impactDetails.technical || impactDetails.business || d.technical_impact || d.business_impact) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <p className="eyebrow mb-1">Impact (technical)</p>
            <p className="text-muted leading-relaxed">{impactDetails.technical || d.technical_impact || '—'}</p>
          </div>
          <div>
            <p className="eyebrow mb-1">Impact (business)</p>
            <p className="text-muted leading-relaxed">{impactDetails.business || d.business_impact || '—'}</p>
          </div>
        </div>
      )}

      {d.rule_id && (
        <div className="flex items-center gap-2">
          <p className="eyebrow">Source test</p>
          <span className="mono-cell text-[10px] text-faint">{d.source_test || '—'}</span>
          {d.rule_id && <span className="mono-cell text-[10px] text-faint">{d.rule_id}</span>}
        </div>
      )}

      {d.validation_reason && (
        <div>
          <p className="eyebrow mb-1">Deterministic validation</p>
          <p className="text-muted leading-relaxed">{d.validation_reason}</p>
        </div>
      )}

      {(d.first_seen || d.last_seen) && (
        <div className="grid grid-cols-2 gap-3">
          <KV label="First seen" value={d.first_seen ? formatDateTime(d.first_seen) : '—'} />
          <KV label="Last seen" value={d.last_seen ? formatDateTime(d.last_seen) : '—'} />
        </div>
      )}

      {d.proof_of_concept && d.proof_of_concept.request && (
        <div>
          <p className="eyebrow mb-1.5">Proof of concept</p>
          <div className="rounded-xl border border-line p-3 space-y-1 mb-2 text-[10.5px]">
            <p className="mono-cell text-faint">
              {d.proof_of_concept.request.method} {d.proof_of_concept.request.endpoint || ''}
              {d.proof_of_concept.request.parameter ? ` (param: ${d.proof_of_concept.request.parameter})` : ''}
            </p>
            <p className="text-muted"><span className="text-faint">expected:</span> {d.proof_of_concept.expected_behavior || '—'}</p>
            <p className="text-muted"><span className="text-faint">observed:</span> {d.proof_of_concept.observed_behavior || '—'}</p>
            <p className="text-muted"><span className="text-faint">validation:</span> {d.proof_of_concept.validation_logic || '—'}</p>
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap rounded-xl border border-line bg-surface-2 p-3 font-mono text-[10px] text-muted">
            {d.proof_of_concept.steps_to_reproduce}
          </pre>
        </div>
      )}

      {((Array.isArray(d.evidence) && d.evidence.length > 0) ||
        (Array.isArray(vuln.evidence_records) && vuln.evidence_records.length > 0)) && (
        <div>
          <p className="eyebrow mb-1.5">Structured evidence</p>
          <div className="space-y-1.5">
            {(
              Array.isArray(d.evidence) && d.evidence.length > 0
                ? d.evidence
                : Array.isArray(vuln.evidence_records)
                ? vuln.evidence_records
                : []
            ).map((e: any) => {
              const integrity = e.integrity || {};
              const ok = integrity.request_ok !== false && integrity.response_ok !== false;
              return (
                <div key={e.evidence_id ?? e.id} className="rounded-xl border border-line p-3 text-[10.5px]">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <span className="mono-cell text-[10px] text-accent">{e.evidence_type}</span>
                    {e.observation_id != null && (
                      <span className="mono-cell text-[10px] text-faint">observation #{e.observation_id}</span>
                    )}
                    <span className="mono-cell text-[10px] text-faint">{e.redaction_status}</span>
                    <span className="mono-cell text-[10px] text-faint">{e.security_boundary}</span>
                    {integrity.status && (
                      <span className={`mono-cell text-[10px] ${ok ? 'text-accent' : 'text-critical'}`}>
                        integrity: {ok ? 'ok' : 'MISMATCH'}
                      </span>
                    )}
                  </div>
                  <p className="text-muted"><span className="text-faint">expected:</span> {e.expected || '—'}</p>
                  <p className="text-muted"><span className="text-faint">actual:</span> {e.actual || '—'}</p>
                  {(e.request_hash || e.response_hash) && (
                    <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-1 text-[9.5px] text-faint">
                      <span>req-hash: {e.request_hash ? e.request_hash.slice(0, 16) : '—'}</span>
                      <span>resp-hash: {e.response_hash ? e.response_hash.slice(0, 16) : '—'}</span>
                      {(e.original_size != null || e.captured_size != null) && (
                        <span>
                          captured {e.captured_size ?? '—'}/{e.original_size ?? '—'} bytes{e.truncated ? ' (truncated)' : ''}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {Array.isArray(d.history) && d.history.length > 0 && (
        <div>
          <p className="eyebrow mb-1.5">Lifecycle history</p>
          <div className="space-y-1">
            {d.history.map((h: any, i: number) => (
              <div key={i} className="flex items-start gap-2 text-[10.5px] font-mono">
                <span className="text-faint shrink-0">{h.created_at || '—'}</span>
                <span className={`shrink-0 ${LIFECYCLE_TONES[h.from_status] || 'text-faint'}`}>{h.from_status}</span>
                <span className="text-faint shrink-0">→</span>
                <span className={`shrink-0 ${LIFECYCLE_TONES[h.to_status] || 'text-faint'}`}>{h.to_status}</span>
                <span className="text-faint shrink-0">by {h.actor || 'system'}</span>
                <span className="text-muted truncate" title={h.reason || ''}>{h.reason || ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {Array.isArray(d.proof_of_concept?.safety_constraints) && d.proof_of_concept.safety_constraints.length > 0 && (
        <div>
          <p className="eyebrow mb-1">Safety constraints</p>
          <ul className="list-disc pl-4 space-y-0.5 text-[10.5px] text-faint">
            {d.proof_of_concept.safety_constraints.map((c: string, i: number) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
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