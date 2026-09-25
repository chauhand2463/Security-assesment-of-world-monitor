import React, { useState, useEffect, useCallback } from 'react';
import { Radar, AlertTriangle, Target, Network, ArrowRight, Footprints, Layers, Crosshair, Info } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { apiFetch, getScanCoverage } from '../api';
import type { SurfaceCoverage } from '../api';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityText } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { Skeleton, SkeletonTable } from '../components/Skeleton';
import { DataTable } from '../components/DataTable';
import { Reveal } from '../components/Reveal';
import { relativeTime } from '../components/format';

export const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [agg, setAgg] = useState<any>(null);
  const [surface, setSurface] = useState<SurfaceCoverage | null>(null);
  const [latestScanId, setLatestScanId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [scanRes, summaryRes, aggRes] = await Promise.all([
        apiFetch('/scans/list'),
        apiFetch('/scans/summary'),
        apiFetch('/dashboard/summary'),
      ]);
      if (scanRes.ok) {
        const rows = await scanRes.json();
        setScans(rows);
        setError('');
        const latest = [...rows].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
        if (latest) {
          setLatestScanId(latest.id);
          const cov = await getScanCoverage(latest.id);
          setSurface(cov?.surface ?? null);
        } else {
          setLatestScanId(null);
          setSurface(null);
        }
      } else if (!summaryRes.ok) {
        const errData = await summaryRes.json().catch(() => null);
        setError(errData?.detail || 'Failed to load assessment data.');
      }
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
      if (aggRes.ok) {
        setAgg(await aggRes.json());
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const latestScans = (raw: any[], count = 6) =>
    [...raw].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, count);

  const navigate = useNavigate();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Overview"
        title="Assessment overview"
        description="Live status of assessment operations, latest assessments, and open findings."
        actions={
          <Link
            to="/scan/new"
            className="group inline-flex items-center gap-2 rounded-full border border-accent/60 bg-accent px-5 py-2.5 text-[12.5px] font-medium text-[#04140e] shadow-[0_12px_32px_-18px_rgba(24,185,138,0.9)] no-underline transition-[background-color,box-shadow,transform] duration-500 ease-spring hover:bg-accent-bright active:scale-[0.98]"
          >
            <Radar className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
            New Assessment
            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-[#04140e]/10 transition-transform duration-500 ease-spring group-hover:translate-x-0.5">
              <ArrowRight className="h-3 w-3" strokeWidth={1.75} aria-hidden="true" />
            </span>
          </Link>
        }
      />

      {/* Security posture hero — every figure is a persisted count, never an estimate */}
      <Reveal delay={0}>
        <section className="relative overflow-hidden rounded-2xl border border-accent/20 bg-gradient-to-br from-accent/[0.07] via-surface-2/40 to-transparent p-6">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="min-w-0 max-w-[52ch]">
              <p className="eyebrow mb-2">Security posture</p>
              <h2 className="display text-[20px] font-semibold leading-tight text-text">
                Evidence-backed posture, derived only from persisted records
              </h2>
              <p className="mt-2 text-[11.5px] leading-relaxed text-muted">
                Confirmed findings are validated against deterministic evidence; candidates await verification;
                every observation is stored before any finding is derived. Totals come straight from the backend
                aggregate — nothing on this dashboard is synthesized.
              </p>
            </div>
            <div className="grid w-full grid-cols-2 gap-3 sm:w-auto sm:grid-cols-4">
              <HeroStat
                label="Confirmed findings"
                value={agg?.confirmed_findings ?? 0}
                note="evidence-validated"
                tone="text-accent"
                to="/findings"
              />
              <HeroStat
                label="Candidates"
                value={agg?.candidate_findings ?? 0}
                note="awaiting verification"
                tone="text-low"
                to="/findings"
              />
              <HeroStat
                label="Evidence records"
                value={agg?.observation_count ?? 0}
                note="persisted observations"
                tone="text-text"
                to="/coverage"
              />
              <HeroStat
                label="Assessments run"
                value={agg?.scans_total ?? scans.length}
                note="persisted scan ledger"
                tone="text-text"
                to="/scans"
              />
            </div>
          </div>
        </section>
      </Reveal>

      {/* Stat tiles */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Reveal delay={0}>
          <StatTile
            label="Assessments Run"
            icon={<Target className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            loading={loading}
            iconTone="text-accent"
          >
            {scans.length}
            <span className="text-[10px] font-normal text-faint">total</span>
          </StatTile>
        </Reveal>
        <Reveal delay={0.05}>
          <StatTile
            label="Open Findings"
            icon={<AlertTriangle className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            loading={loading}
            iconTone="text-critical"
          >
            {summary?.open_findings ?? 0}
          </StatTile>
        </Reveal>
        <Reveal delay={0.08}>
          <StatTile
            label="Validated Findings"
            icon={<Radar className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            loading={loading}
            iconTone="text-accent"
          >
            {agg?.confirmed_findings ?? 0}
            <span className="text-[10px] font-normal text-faint">
              {agg?.candidate_findings ? `+ ${agg.candidate_findings} candidates` : 'validated'}
            </span>
          </StatTile>
        </Reveal>
        <Reveal delay={0.1}>
          <StatTile
            label="Evidence Records"
            icon={<Footprints className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            loading={loading}
            iconTone="text-accent"
          >
            {agg?.observation_count ?? 0}
            <span className="text-[10px] font-normal text-faint">
              {agg?.assets_total ?? 0} assets
            </span>
          </StatTile>
        </Reveal>
        <Reveal delay={0.15}>
          <StatTile
            label="Open Ports"
            icon={<Network className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            loading={loading}
            iconTone="text-low"
          >
            {summary?.open_ports_total ?? 0}
          </StatTile>
        </Reveal>
      </div>

      {/* Latest surface coverage */}
      <Reveal>
        <div className="panel p-5">
          <div className="mb-3.5 flex flex-wrap items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
              <Crosshair className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
              Latest observed surface
            </h2>
            {latestScanId != null ? (
              <Link
                to={`/coverage?scan=${latestScanId}`}
                className="group inline-flex items-center gap-1 text-[11.5px] font-medium text-accent no-underline transition-colors duration-500 ease-spring hover:text-accent-bright"
              >
                Full coverage
                <ArrowRight className="h-3 w-3 transition-transform duration-500 ease-spring group-hover:translate-x-0.5" strokeWidth={1.75} aria-hidden="true" />
              </Link>
            ) : (
              <span className="eyebrow">assessment #—</span>
            )}
          </div>
          {loading ? (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {Array.from({ length: 2 }).map((_, i) => (
                <Skeleton key={i} className="h-16 rounded-xl" />
              ))}
            </div>
          ) : surface == null ? (
            <p className="text-[11px] text-faint">
              No observed surface yet — run an assessment and endpoints/parameters will show here from persisted evidence.
            </p>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <MiniStat label="Endpoints assessed" done={surface.endpoints_assessed} total={surface.endpoints_total} tone="bg-accent" />
              <MiniStat label="Parameters assessed" done={surface.parameters_assessed} total={surface.parameters_total} tone="bg-high" />
            </div>
          )}
        </div>
      </Reveal>

      {/* Summary + severity */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Reveal className="lg:col-span-2">
          <section className="panel h-full p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="text-[12.5px] font-semibold text-text">Security Score Trend</h2>
              <span className="eyebrow">Last assessments</span>
            </div>
            <p className="mb-4 flex items-start gap-2 text-[10px] leading-relaxed text-faint">
              <Info className="mt-0.5 h-3 w-3 shrink-0" strokeWidth={1.5} aria-hidden="true" />
              Scores are computed in the backend from confirmed (evidence-validated) findings only — starting at 100 and
              deducting per evidence-backed issue. It is a findings-derived posture signal, not a coverage statistic.
            </p>
            {loading ? (
              <Skeleton className="h-36 w-full" />
            ) : (summary?.score_history ?? []).length === 0 ? (
              <EmptyState
                title="No score history yet"
                description="Run your first assessment to plot the security score trend."
                action={
                  <Link to="/scan/new" className="no-underline">
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-3.5 py-1.5 text-[11.5px] text-muted transition-[border-color,color,background-color] duration-500 ease-spring hover:border-line-strong hover:text-text">
                      Start assessment
                      <ArrowRight className="h-3 w-3" strokeWidth={1.75} aria-hidden="true" />
                    </span>
                  </Link>
                }
              />
            ) : (
              <ScoreBars history={summary.score_history} />
            )}
          </section>
        </Reveal>

        <Reveal delay={0.08}>
          <section className="panel h-full p-5">
            <h2 className="mb-4 text-[12.5px] font-semibold text-text">Severity Distribution</h2>
            {loading ? (
              <Skeleton className="h-36 w-full" />
            ) : (
              <SeverityBreakdown dist={summary?.severity_distribution ?? {}} />
            )}
          </section>
        </Reveal>
      </div>

      {/* Lifecycle + coverage trend */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Reveal>
          <section className="panel h-full p-5">
            <h2 className="mb-4 text-[12.5px] font-semibold text-text">Finding Lifecycle</h2>
            {loading ? (
              <Skeleton className="h-36 w-full" />
            ) : (
              <LifecycleBreakdown lifecycle={agg?.findings_lifecycle ?? {}} />
            )}
          </section>
        </Reveal>
        <Reveal className="lg:col-span-2">
          <section className="panel h-full p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="text-[12.5px] font-semibold text-text">Coverage Trend</h2>
            </div>
            {loading ? (
              <Skeleton className="h-36 w-full" />
            ) : (agg?.coverage_trend ?? []).length === 0 ? (
              <EmptyState
                title="No coverage recorded yet"
                description="Coverage is derived only from the persisted phase-7 scan ledger."
              />
            ) : (
              <CoverageCurve trend={agg.coverage_trend} />
            )}
          </section>
        </Reveal>
      </div>

      {/* Evidence chain */}
      <Reveal>
        <section className="panel overflow-hidden">
          <div className="flex items-center justify-between px-5 pt-5 pb-3">
            <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
              <Layers className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
              Observations (evidence chain)
            </h2>
            <span className="mono-cell text-[10px] text-faint">
              {agg?.observation_count ?? 0} persisted · {agg?.assets_by_type?.asset ?? 0} assets
            </span>
          </div>
          <div className="px-5 pb-5">
            {loading ? (
              <SkeletonTable rows={3} />
            ) : Object.keys(agg?.observations_by_scan ?? {}).length === 0 ? (
              <EmptyState
                title="No observations persisted"
                description="Run a real assessment; every observation is stored before any finding is derived."
              />
            ) : (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4">
                {Object.entries(agg.observations_by_scan).sort(
                  (a, b) => Number(b[1]) - Number(a[1]),
                ).map(([scanId, count]) => (
                  <div key={scanId} className="rounded-xl border border-line bg-surface-2 px-3 py-2.5">
                    <span className="mono-cell block text-[9.5px] text-faint">assessment #{scanId}</span>
                    <span className="tnum mt-0.5 block text-[20px] font-semibold leading-none text-text">{String(count)}</span>
                    <span className="text-[10px] text-muted">observations</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </Reveal>

      {/* Recent scans */}
      <Reveal>
        <section className="panel overflow-hidden">
          <div className="flex items-center justify-between px-5 pt-5 pb-3">
            <h2 className="text-[12.5px] font-semibold text-text">Recent Assessments</h2>
            <Link
              to="/scans"
              className="group inline-flex items-center gap-1 text-[11.5px] font-medium text-accent no-underline transition-colors duration-500 ease-spring hover:text-accent-bright"
            >
              View all
              <ArrowRight className="h-3 w-3 transition-transform duration-500 ease-spring group-hover:translate-x-0.5" strokeWidth={1.75} aria-hidden="true" />
            </Link>
          </div>
          {error ? (
            <div className="px-5 pb-5">
              <ErrorState message={error} onRetry={fetchData} />
            </div>
          ) : loading ? (
            <div className="px-5 pb-5"><SkeletonTable rows={4} /></div>
          ) : scans.length === 0 ? (
            <div className="px-5 pb-5">
              <EmptyState
                title="No assessments yet"
                description="Queue your first assessment to start collecting evidence-backed findings."
                action={
                  <Link to="/scan/new" className="no-underline">
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-3.5 py-1.5 text-[11.5px] text-muted transition-[border-color,color,background-color] duration-500 ease-spring hover:border-line-strong hover:text-text">
                      Queue scan
                      <ArrowRight className="h-3 w-3" strokeWidth={1.75} aria-hidden="true" />
                    </span>
                  </Link>
                }
              />
            </div>
          ) : (
            <DataTable
              columns={[
                { key: 'target', label: 'Target', render: (s: any) => <span className="font-medium text-text">{s.target}</span> },
                {
                  key: 'status',
                  label: 'Status',
                  render: (s: any) => <StatusBadge status={s.status} />,
                },
                {
                  key: 'score',
                  label: 'Score',
                  headerClassName: 'cursor-help',
                  render: (s: any) => (
                    <span className="mono-cell text-muted">{s.security_score !== null ? `${s.security_score}/100` : '—'}</span>
                  ),
                },
                {
                  key: 'coverage',
                  label: 'Coverage',
                  render: (s: any) => (
                    <span className="mono-cell text-muted">{s.coverage !== null ? `${s.coverage}%` : '—'}</span>
                  ),
                },
                {
                  key: 'evidence',
                  label: 'Evidence',
                  render: (s: any) => {
                    const n = agg?.observations_by_scan?.[String(s.id)] ?? 0;
                    return <span className="mono-cell text-[10.5px] text-faint">{n ? `${n} obs` : '—'}</span>;
                  },
                },
                {
                  key: 'created',
                  label: 'Triggered',
                  render: (s: any) => <span className="text-[11px] text-faint">{relativeTime(s.created_at)}</span>,
                },
              ]}
              rows={latestScans(scans)}
              keyField={(s: any) => String(s.id)}
              loading={loading}
              onRowClick={() => navigate('/scans')}
            />
          )}
        </section>
      </Reveal>
    </div>
  );
};

const HeroStat: React.FC<{ label: string; value: number; note: string; tone: string; to: string }> = ({
  label,
  value,
  note,
  tone,
  to,
}) => (
  <Link to={to} className="no-underline">
    <div className="rounded-xl border border-line bg-surface/60 px-3.5 py-3 transition-colors duration-500 ease-spring hover:border-line-strong">
      <p className="eyebrow mb-1.5">{label}</p>
      <p className={`tnum text-[24px] font-semibold leading-none tracking-tight ${tone}`}>{value}</p>
      <p className="mono-cell mt-1.5 text-[9px] text-faint">{note}</p>
    </div>
  </Link>
);

const StatTile: React.FC<{
  label: string;
  icon: React.ReactNode;
  loading?: boolean;
  iconTone?: string;
  children: React.ReactNode;
}> = ({ label, icon, loading, iconTone = 'text-accent', children }) => (
  <div className="panel flex h-full items-center gap-3.5 p-5">
    <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-line bg-surface-2 ${iconTone}`}>
      {icon}
    </span>
    <div className="min-w-0">
      <p className="eyebrow mb-1.5">{label}</p>
      <div className="flex items-baseline gap-1">
        {loading ? (
          <Skeleton className="h-6 w-12" />
        ) : (
          <span className="tnum text-[26px] font-semibold leading-none tracking-tight text-text">{children}</span>
        )}
      </div>
    </div>
  </div>
);

const MiniStat: React.FC<{ label: string; done: number; total: number; tone: string }> = ({
  label,
  done,
  total,
  tone,
}) => {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div className="rounded-xl border border-line bg-surface-2/60 px-3.5 py-3">
      <div className="flex items-baseline justify-between gap-2">
        <p className="text-[11.5px] font-medium text-text">{label}</p>
        <p className="mono-cell text-[10px] text-faint">{done}/{total}</p>
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
        <div className={`h-full rounded-full ${tone} transition-[width] duration-700 ease-spring`} style={{ width: `${pct}%` }} />
      </div>
      <p className="mono-cell mt-1 text-[9.5px] text-faint">
        {total > 0 ? `${pct}% of observed surface covered` : 'nothing observed'}
      </p>
    </div>
  );
};

const LIFECYCLE_META: Array<[string, string]> = [
  ['confirmed', 'Confirmed (validated)'],
  ['candidate', 'Candidate (evidence-backed)'],
  ['rejected', 'Rejected'],
  ['duplicate', 'Duplicate'],
  ['accepted', 'Accepted risk'],
  ['remediated', 'Remediated'],
];

const LifecycleBreakdown: React.FC<{ lifecycle: Record<string, number> }> = ({ lifecycle }) => {
  const total = Object.values(lifecycle).reduce((a, b) => a + b, 0);
  if (total === 0) {
    return (
      <EmptyState
        title="No findings tracked"
        description="Lifecycle buckets populate from persisted finding status transitions."
      />
    );
  }
  const width = (n: number) => `${Math.max(2, Math.round((n / total) * 100))}%`;
  return (
    <div className="space-y-2.5">
      {LIFECYCLE_META.map(([status, label]) => {
        const n = lifecycle[status] ?? 0;
        if (n === 0) return null;
        const accent = status === 'confirmed' ? 'bg-accent'
          : status === 'candidate' ? 'bg-high'
          : status === 'rejected' ? 'bg-faint'
          : 'bg-medium';
        return (
          <div key={status} className="flex items-center gap-2.5">
            <span className="w-32 shrink-0 truncate text-[10.5px] text-muted">{label}</span>
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
              <div className={`h-full rounded-full ${accent}`} style={{ width: width(n) }} />
            </div>
            <span className="mono-cell w-6 text-right text-faint">{n}</span>
          </div>
        );
      })}
    </div>
  );
};

const CoverageCurve: React.FC<{ trend: any[] }> = ({ trend }) => {
  const max = Math.max(1, ...trend.map((t) => Number(t.coverage) || 0));
  const recent = trend.slice(-8);
  return (
    <div className="flex h-36 items-end gap-2">
      {recent.map((t, i) => {
        const v = Math.max(0, Math.min(100, Number(t.coverage) || 0));
        return (
          <div key={t.scan_id ?? i} className="flex min-w-0 flex-1 flex-col items-center gap-1.5">
            <span className="mono-cell text-[9px] text-faint">{Math.round(v)}%</span>
            <div className="flex h-[6.5rem] w-full items-end overflow-hidden rounded-lg bg-surface-2">
              <div
                className="w-full rounded-lg bg-gradient-to-t from-accent/55 to-accent transition-[height] duration-700 ease-spring"
                style={{ height: `${Math.max(4, (v / max) * 100)}%` }}
              />
            </div>
            <span className="mono-cell w-full truncate text-center text-[8px] text-faint">
              #{t.scan_id ?? ''}
            </span>
          </div>
        );
      })}
    </div>
  );
};

const ScoreBars: React.FC<{ history: any[] }> = ({ history }) => (
  <div className="flex h-36 items-end gap-2">
    {history.map((h, i) => {
      const score = Math.max(0, Math.min(100, Number(h.score) || 0));
      return (
        <div key={i} className="flex min-w-0 flex-1 flex-col items-center gap-1.5">
          <span className="mono-cell text-[9px] text-faint">{score}</span>
          <div className="flex h-[6.5rem] w-full items-end overflow-hidden rounded-lg bg-surface-2">
            <div
              className="w-full rounded-lg bg-gradient-to-t from-accent/55 to-accent transition-[height] duration-700 ease-spring"
              style={{ height: `${Math.max(4, score)}%` }}
            />
          </div>
          <span className="mono-cell w-full truncate text-center text-[8px] text-faint">
            {h.target?.split('.').slice(0, 1)[0] ?? ''}
          </span>
        </div>
      );
    })}
  </div>
);

const SeverityBreakdown: React.FC<{ dist: Record<string, number> }> = ({ dist }) => {
  const order = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  const max = Math.max(1, ...Object.values(dist));
  if (total === 0) {
    return (
      <EmptyState
        title="No open findings"
        description="Findings appear here once evidence-backed records are persisted for an assessment."
      />
    );
  }
  return (
    <div className="space-y-3">
      {order.map((sev) => {
        const count = dist[sev] ?? 0;
        if (count === 0) return null;
        return (
          <div key={sev} className="flex items-center gap-2.5">
            <span className="w-16 shrink-0"><SeverityText severity={sev} /></span>
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
              <div
                className={`h-full rounded-full ${sevColorClass(sev)}`}
                style={{ width: `${(count / max) * 100}%` }}
              />
            </div>
            <span className="mono-cell w-6 text-right text-faint">{count}</span>
          </div>
        );
      })}
    </div>
  );
};

function sevColorClass(sev: string): string {
  switch (sev) {
    case 'Critical': return 'bg-critical';
    case 'High': return 'bg-high';
    case 'Medium': return 'bg-medium';
    case 'Low': return 'bg-low';
    default: return 'bg-faint';
  }
}
