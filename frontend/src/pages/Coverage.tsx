import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Eye,
  ClipboardList,
  Zap,
  FileSearch,
  Target,
  ShieldCheck,
  GitCompareArrows,
  Boxes,
  ArrowDown,
  ArrowUp,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { getScanCoverage, getAssessmentPlan, getScanDiff, getScanExecutions } from '../api';
import type { ScanCoverageResponse, AssessmentPlan, AssessmentTask, SurfaceDiff, ToolExecutionRow } from '../api';
import { PageHeader } from '../components/PageHeader';
import { ScanPicker } from '../components/ScanPicker';
import { EmptyState } from '../components/EmptyState';
import { SkeletonPanel } from '../components/Skeleton';
import { StatusBadge } from '../components/StatusBadge';
import { CoverageBar } from '../components/CoverageBar';
import { DataTable } from '../components/DataTable';
import { humanDuration, relativeTime } from '../components/format';

type DiffTab = 'endpoints' | 'parameters';

const pctOf = (done: number, total: number) => (total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0);

export const Coverage: React.FC = () => {
  const [scanId, setScanId] = useState<number | null>(null);
  const [coverage, setCoverage] = useState<ScanCoverageResponse | null>(null);
  const [plan, setPlan] = useState<AssessmentPlan | null>(null);
  const [diff, setDiff] = useState<SurfaceDiff | null>(null);
  const [executions, setExecutions] = useState<ToolExecutionRow[] | null>(null);
  const [diffTab, setDiffTab] = useState<DiffTab>('endpoints');
  const [planFilter, setPlanFilter] = useState<'all' | 'planned' | 'skipped'>('all');
  const [loading, setLoading] = useState(false);

  const fetchAll = useCallback(async (id: number) => {
    setLoading(true);
    setCoverage(null);
    setPlan(null);
    setDiff(null);
    setExecutions(null);
    try {
      const [cov, pl, df, exec] = await Promise.all([
        getScanCoverage(id),
        getAssessmentPlan(id),
        getScanDiff(id),
        getScanExecutions(id),
      ]);
      setCoverage(cov);
      setPlan(pl);
      setDiff(df);
      setExecutions(exec ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (scanId === null) return;
    fetchAll(scanId);
  }, [scanId, fetchAll]);

  /* Every stage below is derived only from persisted rows. */
  const surface = coverage?.surface ?? null;
  const observedEndpoints = surface?.endpoints_total ?? 0;
  const observedParameters = surface?.parameters_total ?? 0;
  const observationsProduced = useMemo(
    () => (executions ?? []).reduce((acc, e) => acc + (e.parsed_observations ?? 0), 0),
    [executions],
  );
  const planCounts = plan
    ? { planned: plan.tests_planned, skipped: plan.tests_skipped, total: plan.tests_total }
    : null;

  const stages = useMemo(() => {
    const list: Stage[] = [
      {
        key: 'observed',
        label: 'Observed',
        icon: <Eye className="h-4 w-4" aria-hidden="true" />,
        value: observedEndpoints + observedParameters,
        sub: `${observedEndpoints} endpoints · ${observedParameters} parameters recovered from persisted observations`,
        linkTo: scanId !== null ? `/surface?scan=${scanId}` : undefined,
        linkLabel: 'Attack surface',
        cta: 'bg-accent/10 border-accent/40 text-accent',
      },
      {
        key: 'planned',
        label: 'Planned',
        icon: <ClipboardList className="h-4 w-4" aria-hidden="true" />,
        value: planCounts?.planned ?? 0,
        sub: planCounts
          ? `of ${planCounts.total} registered tests (${planCounts.skipped} skipped with recorded reasons)`
          : 'no assessment program persisted',
        linkLabel: 'Program below',
      },
      {
        key: 'executed',
        label: 'Executed',
        icon: <Zap className="h-4 w-4" aria-hidden="true" />,
        value: (executions ?? []).length,
        sub: coverage
          ? `${coverage.completed_tasks}/${coverage.total_tasks} tasks completed · ${coverage.completed_tools}/${coverage.total_tools} tool runs finished`
          : 'no execution rows persisted',
      },
      {
        key: 'evidence',
        label: 'Evidence',
        icon: <FileSearch className="h-4 w-4" aria-hidden="true" />,
        value: observationsProduced,
        sub: 'observations persisted from tool execution; findings trace to these records',
        linkTo: scanId !== null ? `/scans/${scanId}/timeline` : undefined,
        linkLabel: 'Timeline',
        cta: 'bg-accent/10 border-accent/40 text-accent',
      },
    ];
    return list;
  }, [observedEndpoints, observedParameters, observationsProduced, planCounts, coverage, executions, scanId]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Inventory / Coverage"
        title="Assessment coverage"
        description="One deterministic pipeline per assessment — surface observed, tests planned, tools executed, evidence persisted. Every number is derived from persisted rows; nothing is estimated."
        actions={<ScanPicker value={scanId} onChange={setScanId} />}
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
      ) : loading ? (
        <div className="space-y-4">
          <SkeletonPanel className="min-h-[120px]" />
          <SkeletonPanel className="min-h-[300px]" />
          <SkeletonPanel className="min-h-[300px]" />
        </div>
      ) : !coverage ? (
        <EmptyState title="Coverage unavailable" description="This assessment has no recorded coverage data." />
      ) : (
        <>
          {/* Pipeline band: Observed → Planned → Executed → Evidence */}
          <section className="panel p-5" aria-label="Observation to evidence pipeline">
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                <ShieldCheck className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                Observed → planned → executed → evidence
              </h2>
              <span className="mono-cell text-[10px] text-faint">
                {coverage.target} · #{coverage.scan_id}
              </span>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {stages.map((s) => (
                <StageCard key={s.key} stage={s} />
              ))}
            </div>
            <p className="mt-3 text-[10px] leading-relaxed text-faint">
              The band is exactly the persisted evidence chain: discovery observations define the surface, the plan
              targets only what was observed, executions record tool runs with parsed observation counts, and every
              finding references observation records. Nothing in this band is synthesized.
            </p>
          </section>

          {/* Program + execution ledger */}
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            {plan && (
              <section className="panel overflow-hidden" id="program">
                <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-3">
                  <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                    <ClipboardList className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                    Assessment program
                  </h2>
                  <span className="mono-cell text-[10px] text-faint">
                    {plan.tests_planned} planned · {plan.tests_skipped} skipped of {plan.tests_total}
                  </span>
                </div>
                <div className="px-5 pb-3">
                  <div className="flex items-center gap-3">
                    <div className="h-1.5 w-full max-w-[240px] overflow-hidden rounded-full bg-surface-2">
                      <div
                        className="h-full rounded-full bg-accent transition-[width] duration-700 ease-spring"
                        style={{ width: `${pctOf(plan.tests_planned, plan.tests_total)}%` }}
                      />
                    </div>
                    <span className="mono-cell text-[10px] text-faint">
                      plan covers {pctOf(plan.tests_planned, plan.tests_total)}% of the registry
                    </span>
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-faint">
                    Deterministic program: planned tests target observed endpoints and parameters only; skipped tests
                    always record a reason. Generated {new Date(plan.generated_at).toISOString().slice(0, 16).replace('T', ' ')} UTC.
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
                      aria-pressed={planFilter === f}
                    >
                      {f}
                    </button>
                  ))}
                </div>
                <div className="scrollbar-thin max-h-80 overflow-y-auto px-5 pb-5">
                  {plan.tasks.filter((t) => planFilter === 'all' || t.status === planFilter).map((task) => (
                    <PlanRow key={task.test_id} task={task} />
                  ))}
                </div>
              </section>
            )}

            <section className="panel overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-2">
                <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                  <Zap className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                  Tool execution ledger
                </h2>
                <span className="mono-cell text-[10px] text-faint">
                  {observationsProduced} observations produced
                </span>
              </div>
              <DataTable
                rows={executions}
                keyField={(e: ToolExecutionRow) => `${e.id}-${e.tool}-${e.attempt}`}
                empty={{
                  title: 'No executions recorded',
                  description: 'Tool execution rows appear once a tool run is persisted.',
                }}
                columns={[
                  {
                    key: 'tool',
                    label: 'Tool',
                    render: (e: ToolExecutionRow) => (
                      <span className="mono-cell text-[11px] text-text">{e.tool}</span>
                    ),
                  },
                  {
                    key: 'stage_tool',
                    label: 'Stage',
                    render: (e: ToolExecutionRow) => (
                      <span className="mono-cell text-[9.5px] text-faint">{e.stage}</span>
                    ),
                  },
                  {
                    key: 'status',
                    label: 'Status',
                    render: (e: ToolExecutionRow) => <StatusBadge status={e.status} />,
                  },
                  {
                    key: 'attempt',
                    label: 'Try',
                    render: (e: ToolExecutionRow) => (
                      <span className="mono-cell text-[9.5px] text-faint">{e.attempt}</span>
                    ),
                  },
                  {
                    key: 'obs',
                    label: 'Obs parsed',
                    render: (e: ToolExecutionRow) => (
                      <span className="mono-cell text-[10px] text-muted">{e.parsed_observations}</span>
                    ),
                  },
                  {
                    key: 'duration',
                    label: 'Duration',
                    render: (e: ToolExecutionRow) => (
                      <span className="mono-cell text-[9.5px] text-faint">{humanDuration(e.duration_ms)}</span>
                    ),
                  },
                  {
                    key: 'started',
                    label: 'Started',
                    render: (e: ToolExecutionRow) => (
                      <span className="mono-cell text-[9.5px] text-faint">{relativeTime(e.started_at)}</span>
                    ),
                  },
                ]}
              />
              <p className="px-5 pt-3 pb-5 text-[10px] leading-relaxed text-faint">
                Rows come from `ToolExecution`; the parsed-observation count is part of the persisted record, so the
                evidence stage above never estimates yield.
              </p>
            </section>
          </div>

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
                    label="Endpoints assessed (executed/validated/failed tests)"
                    done={surface.endpoints_assessed}
                    total={surface.endpoints_total}
                    tone="bg-accent"
                  />
                  <CoverageBar
                    label="Parameters assessed (enabled by owning endpoint)"
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
                <p className="text-[11px] text-faint">{diff?.note || 'No previous scan to compare against.'}</p>
              ) : (
                <>
                  <div className="mb-3 flex flex-wrap items-center gap-1.5">
                    {(['endpoints', 'parameters'] as const).map((t) => (
                      <button
                        key={t}
                        onClick={() => setDiffTab(t)}
                        className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[10px] transition-colors duration-500 ease-spring ${
                          diffTab === t ? 'border-accent/60 text-accent bg-accent/10' : 'border-line text-faint hover:text-muted'
                        }`}
                        aria-pressed={diffTab === t}
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

type StageKey = 'observed' | 'planned' | 'executed' | 'evidence';

interface Stage {
  key: StageKey;
  label: string;
  icon: React.ReactNode;
  value: number;
  sub: string;
  linkTo?: string;
  linkLabel?: string;
  cta?: string;
}

const StageCard: React.FC<{ stage: Stage }> = ({ stage }) => (
  <div className="relative overflow-hidden rounded-2xl border border-line bg-surface-2/50 p-4">
      <div className="flex items-center justify-between gap-2">
        <span className={`inline-flex h-8 w-8 items-center justify-center rounded-xl border ${stage.cta ?? 'border-line bg-white/[0.02] text-muted'}`}>
          {stage.icon}
        </span>
        <span className="mono-cell text-[9px] uppercase tracking-wider text-faint">step {['observed', 'planned', 'executed', 'evidence'].indexOf(stage.key) + 1}/4</span>
      </div>
      <p className="mt-3 text-[10.5px] font-medium uppercase tracking-wider text-faint">{stage.label}</p>
      <p className="tnum mt-1 text-[26px] font-semibold leading-none tracking-tight text-text">{stage.value}</p>
      <p className="mt-2 min-h-0 text-[10px] leading-relaxed text-muted">{stage.sub}</p>
      {stage.linkTo && stage.linkLabel && (
        <Link
          to={stage.linkTo}
          className="soft-link mt-2 inline-flex items-center text-[10.5px]"
        >
          {stage.linkLabel} →
        </Link>
      )}
    </div>
  );

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
  <div className="mb-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-line px-3 py-2.5">
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
    <p className={`eyebrow mb-2 flex items-center gap-1.5 ${tone}`}>{icon}{title} ({items.length})</p>
    {items.length === 0 ? (
      <p className="text-[10.5px] text-faint">Nothing changed.</p>
    ) : (
      <div className="scrollbar-thin max-h-40 space-y-1 overflow-y-auto">
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