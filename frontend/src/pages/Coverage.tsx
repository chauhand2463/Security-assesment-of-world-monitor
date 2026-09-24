import React, { useState, useEffect, useCallback } from 'react';
import {
  Target,
  Layers,
  ShieldCheck,
  GitCompareArrows,
  Fingerprint,
  Boxes,
  Network,
  ArrowDown,
  ArrowUp,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  getScanCoverage,
  getScanDiff,
  getAssessmentPlan,
} from '../api';
import type {
  ScanCoverageResponse,
  AssessmentPlan,
  AssessmentTask,
  SurfaceDiff,
} from '../api';
import { PageHeader } from '../components/PageHeader';
import { ScanPicker } from '../components/ScanPicker';
import { EmptyState } from '../components/EmptyState';
import { SkeletonPanel } from '../components/Skeleton';
import { formatDateTime } from '../components/format';

type DiffTab = 'endpoints' | 'parameters';

export const Coverage: React.FC = () => {
  const [scanId, setScanId] = useState<number | null>(null);
  const [coverage, setCoverage] = useState<ScanCoverageResponse | null>(null);
  const [plan, setPlan] = useState<AssessmentPlan | null>(null);
  const [diff, setDiff] = useState<SurfaceDiff | null>(null);
  const [diffTab, setDiffTab] = useState<DiffTab>('endpoints');
  const [planFilter, setPlanFilter] = useState<'all' | 'planned' | 'skipped'>('all');
  const [loading, setLoading] = useState(false);

  const fetchAll = useCallback(async (id: number) => {
    setLoading(true);
    setCoverage(null);
    setPlan(null);
    setDiff(null);
    try {
      const [cov, pl, df] = await Promise.all([
        getScanCoverage(id),
        getAssessmentPlan(id),
        getScanDiff(id),
      ]);
      setCoverage(cov);
      setPlan(pl);
      setDiff(df);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (scanId === null) return;
    fetchAll(scanId);
  }, [scanId, fetchAll]);

  const surface = coverage?.surface;
  const surfacePct = (done: number, total: number) => (total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Inventory / Coverage"
        title="Assessment coverage"
        description="Observed surface vs. actually assessed, per assessment — planned tests, executed tools, observed dimensions, and drift vs. the previous run."
        actions={
          <ScanPicker value={scanId} onChange={setScanId} />
        }
      />

      {scanId === null ? (
        <EmptyState
          icon={<Target className="h-4 w-4" aria-hidden="true" />}
          title="No assessments to inspect"
          description="Coverage is derived from persisted assessment runs. Queue an assessment first."
          action={
            <Link to="/scan/new" className="no-underline">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3.5 py-1.5 text-[11.5px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20">
                Queue an assessment
              </span>
            </Link>
          }
        />
      ) : loading && !coverage ? (
        <div className="space-y-4">
          <SkeletonPanel className="min-h-[120px]" />
          <SkeletonPanel className="min-h-[240px]" />
          <SkeletonPanel className="min-h-[240px]" />
        </div>
      ) : !coverage ? (
        <EmptyState title="Coverage unavailable" description="This assessment has no recorded coverage data." />
      ) : (
        <>
          {/* Headline metrics */}
          {surface && (
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <Metric
                icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />}
                label="Scan coverage"
                value={`${coverage.coverage ?? 0}%`}
                sub={`${coverage.completed_tasks}/${coverage.total_tasks} tasks`}
              />
              <Metric
                icon={<Layers className="h-4 w-4" aria-hidden="true" />}
                label="Tool progress"
                value={`${coverage.completed_tools}/${coverage.total_tools}`}
                sub={`${coverage.percent}% complete`}
              />
              <Metric
                icon={<Target className="h-4 w-4" aria-hidden="true" />}
                label="Endpoints assessed"
                value={`${surface.endpoints_assessed}/${surface.endpoints_total}`}
                sub={surfacePct(surface.endpoints_assessed, surface.endpoints_total) ? `${surfacePct(surface.endpoints_assessed, surface.endpoints_total)}% of observed` : 'nothing observed'}
              />
              <Metric
                icon={<Fingerprint className="h-4 w-4" aria-hidden="true" />}
                label="Parameters assessed"
                value={`${surface.parameters_assessed}/${surface.parameters_total}`}
                sub={surfacePct(surface.parameters_assessed, surface.parameters_total) ? `${surfacePct(surface.parameters_assessed, surface.parameters_total)}% of observed` : 'nothing observed'}
              />
            </div>
          )}

          {/* Assessment plan */}
          {plan && (
            <section className="panel overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-3">
                <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                  <Target className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                  Deterministic assessment program
                </h2>
                <span className="mono-cell text-[10px] text-faint">
                  {plan.tests_planned} planned · {plan.tests_skipped} skipped of {plan.tests_total} registered
                </span>
              </div>

              {/* plan progress */}
              <div className="px-5 pb-3">
                <div className="flex items-center gap-3">
                  <div className="h-1.5 w-full max-w-[260px] overflow-hidden rounded-full bg-surface-2">
                    <div
                      className="h-full rounded-full bg-accent transition-[width] duration-700 ease-spring"
                      style={{ width: `${surfacePct(plan.tests_planned, plan.tests_total)}%` }}
                    />
                  </div>
                  <span className="mono-cell text-[10px] text-faint">
                    plan covers <span className="text-muted">{surfacePct(plan.tests_planned, plan.tests_total)}%</span> of the registry
                  </span>
                </div>
                <p className="mt-2 text-[10px] leading-relaxed text-faint">
                  17 registered tests · endpoint-scoped categories: headers, cors, cookies, methods, redirects, tls,
                  disclosure · parameter-scoped: xss, sqli, ssti, ssrf, idor, authorization, auth, jwt, oauth, graphql
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-1.5 px-5 pb-3">
                {(['all', 'planned', 'skipped'] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setPlanFilter(f)}
                    className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[10px] transition-colors duration-500 ease-spring ${
                      planFilter === f ? 'border-accent/60 text-accent bg-accent/10' : 'border-line text-faint hover:text-muted'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>

              <div className="max-h-72 overflow-y-auto px-5 pb-5">
                {plan.tasks.filter((t) => planFilter === 'all' || t.status === planFilter).map((task) => (
                  <PlanRow key={task.test_id} task={task} />
                ))}
              </div>
            </section>
          )}

          {/* Dimensions + surface coverage */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section className="panel p-5">
              <h2 className="mb-3 flex items-center gap-2 text-[12.5px] font-semibold text-text">
                <Boxes className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                Observed dimensions
              </h2>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <DimCard label="Hosts" dim={coverage.dimensions?.hosts} />
                <DimCard label="Ports" dim={coverage.dimensions?.ports} />
                <DimCard label="URLs" dim={coverage.dimensions?.urls} />
              </div>
            </section>

            {surface && (
              <section className="panel p-5">
                <h2 className="mb-4 flex items-center gap-2 text-[12.5px] font-semibold text-text">
                  <ShieldCheck className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                  Surface coverage
                </h2>
                <div className="space-y-4">
                  <CoverageBar
                    label="Endpoints"
                    done={surface.endpoints_assessed}
                    total={surface.endpoints_total}
                    tone="bg-accent"
                  />
                  <CoverageBar
                    label="Parameters"
                    done={surface.parameters_assessed}
                    total={surface.parameters_total}
                    tone="bg-high"
                  />
                </div>
                <p className="mt-3 text-[10px] leading-relaxed text-faint">{surface.note}</p>
              </section>
            )}
          </div>

          {/* Diff vs previous scan */}
          <section className="panel overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-3">
              <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                <GitCompareArrows className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                Surface drift
              </h2>
              {diff?.compare_to !== scanId && diff?.compare_to != null && (
                <span className="mono-cell text-[10px] text-faint">vs assessment #{diff.compare_to}</span>
              )}
            </div>
            <div className="px-5 pb-5">
              {!diff || diff.compare_to == null ? (
                <p className="text-[11px] text-faint">
                  {diff?.note || 'No previous scan to compare against.'}
                </p>
              ) : (
                <>
                  <div className="flex flex-wrap items-center gap-1.5 mb-3">
                    {(['endpoints', 'parameters'] as const).map((t) => (
                      <button
                        key={t}
                        onClick={() => setDiffTab(t)}
                        className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[10px] transition-colors duration-500 ease-spring ${
                          diffTab === t ? 'border-accent/60 text-accent bg-accent/10' : 'border-line text-faint hover:text-muted'
                        }`}
                      >
                        {t}
                      </button>
                    ))}
                    <span className="mono-cell ml-auto text-[9.5px] text-faint">{diff.note}</span>
                  </div>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <DiffList
                      title="Added"
                      icon={<ArrowDown className="h-3 w-3" aria-hidden="true" />}
                      tone="text-accent"
                      items={diffTab === 'endpoints' ? diff.endpoints_added : diff.parameters_added}
                    />
                    <DiffList
                      title="Removed"
                      icon={<ArrowUp className="h-3 w-3" aria-hidden="true" />}
                      tone="text-critical"
                      items={diffTab === 'endpoints' ? diff.endpoints_removed : diff.parameters_removed}
                    />
                  </div>
                </>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
};

const Metric: React.FC<{ icon: React.ReactNode; label: string; value: string; sub: string }> = ({
  icon,
  label,
  value,
  sub,
}) => (
  <div className="panel flex h-full flex-col gap-1.5 p-5">
    <p className="eyebrow flex items-center gap-1.5">{icon}{label}</p>
    <p className="tnum text-[22px] font-semibold leading-none tracking-tight text-text">{value}</p>
    <p className="mono-cell text-[10px] text-faint">{sub}</p>
  </div>
);

const CoverageBar: React.FC<{ label: string; done: number; total: number; tone: string }> = ({
  label,
  done,
  total,
  tone,
}) => {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[11.5px] font-medium text-text">{label}</span>
        <span className="mono-cell text-[10px] text-faint">
          {done}/{total} assessed
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-surface-2">
        <div className={`h-full rounded-full ${tone} transition-[width] duration-700 ease-spring`} style={{ width: `${pct}%` }} />
      </div>
      <p className="mono-cell mt-1 text-[9.5px] text-faint">{pct}% covered</p>
    </div>
  );
};

const DimCard: React.FC<{ label: string; dim?: { distinct?: unknown[]; observed?: number; tools?: string[] } }> = ({
  label,
  dim,
}) => {
  const distinct = dim?.distinct || [];
  const shown = distinct.slice(0, 6);
  const singular = label.toLowerCase() === 'ports' ? 'port' : label.toLowerCase() === 'urls' ? 'url' : 'host';
  return (
    <div className="rounded-xl border border-line bg-surface-2/60 px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11.5px] font-medium text-text">{label}</span>
        <span className="mono-cell text-[10px] text-faint">{dim?.observed ?? 0} observed</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {shown.length === 0 ? (
          <span className="mono-cell text-[9.5px] text-faint">no {singular}s observed</span>
        ) : (
          shown.map((v) => (
            <span key={String(v)} className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9.5px] text-muted" title={String(v)}>
              {String(v)}
            </span>
          ))
        )}
        {distinct.length > shown.length && (
          <span className="mono-cell text-[9.5px] text-faint">+{distinct.length - shown.length} more</span>
        )}
      </div>
      {(dim?.tools?.length ?? 0) > 0 && (
        <p className="mono-cell mt-1.5 text-[9px] text-faint">captured by: {(dim?.tools ?? []).join(', ')}</p>
      )}
    </div>
  );
};

const PlanRow: React.FC<{ task: AssessmentTask }> = ({ task }) => (
  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-line px-3 py-2.5 mb-1.5">
    <span
      className={`mono-cell shrink-0 rounded-md px-1.5 py-0.5 text-[9px] uppercase tracking-wide ${
        task.status === 'planned' ? 'border border-accent/40 bg-accent/5 text-accent' : 'border border-line text-faint'
      }`}
    >
      {task.status}
    </span>
    <span className="mono-cell w-52 shrink-0 truncate text-[11px] text-text" title={task.test_id}>
      {task.test_id}
    </span>
    <span className="w-24 shrink-0 truncate text-[10.5px] text-muted" title={task.name}>
      {task.name}
    </span>
    <span className="min-w-0 flex-1 truncate text-[10px] text-faint" title={task.reason}>
      {task.reason}
    </span>
    {task.endpoints.length === 1 && (
      <span className="mono-cell hidden max-w-[220px] shrink-0 truncate text-[9.5px] text-accent/80 xl:block" title={task.endpoints[0]}>
        {task.endpoints[0]}
      </span>
    )}
  </div>
);

const DiffList: React.FC<{ title: string; icon: React.ReactNode; tone: string; items: string[] }> = ({
  title,
  icon,
  tone,
  items,
}) => (
  <div className="rounded-xl border border-line bg-surface-2/60 p-3">
    <p className={`eyebrow flex items-center gap-1.5 mb-2 ${tone}`}>{icon}{title} ({items.length})</p>
    {items.length === 0 ? (
      <p className="text-[10.5px] text-faint">Nothing changed.</p>
    ) : (
      <div className="max-h-40 space-y-1 overflow-y-auto">
        {items.map((item) => (
          <p key={item} className="mono-cell truncate text-[10px] text-muted" title={item}>
            {item}
          </p>
        ))}
      </div>
    )}
  </div>
);

export default Coverage;