import React from 'react';
import { EmptyState } from '../EmptyState';
import { Skeleton } from '../Skeleton';
import { SectionHeader } from '../SectionHeader';
import { Card } from '../Card';

type LifecycleRecord = Record<string, number>;

const LIFECYCLE_META: Array<{ status: string; label: string; tone: string }> = [
  { status: 'confirmed', label: 'Confirmed (validated)', tone: 'bg-accent' },
  { status: 'candidate', label: 'Candidate (evidence-backed)', tone: 'bg-high' },
  { status: 'rejected', label: 'Rejected', tone: 'bg-faint' },
  { status: 'duplicate', label: 'Duplicate', tone: 'bg-neutral' },
  { status: 'accepted', label: 'Accepted risk', tone: 'bg-medium' },
  { status: 'remediated', label: 'Remediated', tone: 'bg-accent' },
];

const LifecycleRows: React.FC<{ lifecycle: LifecycleRecord }> = ({ lifecycle }) => {
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
      {LIFECYCLE_META.map(({ status, label, tone }) => {
        const n = lifecycle[status] ?? 0;
        if (n === 0) return null;
        return (
          <div key={status} className="flex items-center gap-2.5">
            <span className="w-32 shrink-0 truncate text-[10.5px] text-muted">{label}</span>
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
              <div
                className={`h-full rounded-full ${tone} transition-[width] duration-700 ease-spring`}
                style={{ width: width(n) }}
              />
            </div>
            <span className="mono-cell w-6 shrink-0 text-right text-faint">{n}</span>
          </div>
        );
      })}
    </div>
  );
};

interface CoverageDatum {
  scan_id: number;
  target?: string;
  coverage?: number | null;
  created_at?: string | null;
}

const CoverageRows: React.FC<{ trend: CoverageDatum[] | null }> = ({ trend }) => {
  const rows = [...(trend ?? [])].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at))).slice(-8);
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No coverage recorded yet"
        description="Coverage is derived only from the persisted scan ledger."
      />
    );
  }
  const max = Math.max(1, ...rows.map((t) => Number(t.coverage) || 0));
  return (
    <div className="flex h-36 items-end gap-2">
      {rows.map((t) => {
        const v = t.coverage == null ? null : Math.max(0, Math.min(100, Number(t.coverage)));
        return (
          <div key={t.scan_id} className="flex min-w-0 flex-1 flex-col items-center gap-1.5">
            <span className="mono-cell text-[9px] text-faint">{v == null ? '—' : `${Math.round(v)}%`}</span>
            <div className="flex h-[6.5rem] w-full items-end overflow-hidden rounded-lg bg-surface-2">
              <div
                className={`w-full rounded-lg transition-[height] duration-700 ease-spring ${
                  v == null ? 'bg-white/[0.04]' : 'bg-gradient-to-t from-accent/55 to-accent'
                }`}
                style={{ height: v == null ? '4%' : `${Math.max(4, (v / max) * 100)}%` }}
              />
            </div>
            <span className="mono-cell w-full truncate text-center text-[8px] text-faint">#{t.scan_id}</span>
          </div>
        );
      })}
    </div>
  );
};

interface FindingsLifecyclePanelProps {
  lifecycle: LifecycleRecord | null | undefined;
  coverageTrend: CoverageDatum[] | null | undefined;
  openFindings: number | null | undefined;
  confirmedFindings: number | null | undefined;
  remediated: number | null | undefined;
  loading: boolean;
}

export const FindingsLifecyclePanel: React.FC<FindingsLifecyclePanelProps> = ({
  lifecycle,
  coverageTrend,
  openFindings,
  confirmedFindings,
  remediated,
  loading,
}) => {
  const flow =
    openFindings != null && confirmedFindings != null ? (
      <div className="mt-5 flex flex-wrap items-center gap-x-2 gap-y-1 border-t border-line pt-3 font-mono text-[10px] text-muted">
        <span>
          Open <span className="tnum text-text">{openFindings}</span>
        </span>
        <span className="text-faint" aria-hidden="true">
          →
        </span>
        <span>
          Validated <span className="tnum text-accent">{confirmedFindings}</span>
        </span>
        {remediated != null && remediated > 0 && (
          <>
            <span className="text-faint" aria-hidden="true">
              →
            </span>
            <span>
              Resolved <span className="tnum text-text">{remediated}</span>
            </span>
          </>
        )}
      </div>
    ) : null;

  return (
    <Card className="overflow-hidden">
      <div className="grid grid-cols-1 xl:grid-cols-3 xl:gap-0">
        <div className="min-w-0 border-b border-line p-5 xl:border-b-0 xl:border-r">
          <SectionHeader title="Findings lifecycle" meta="persisted status buckets" />
          <div className="mt-4">
            {loading ? <Skeleton className="h-32 w-full" /> : <LifecycleRows lifecycle={lifecycle ?? {}} />}
          </div>
          {flow}
        </div>

        <div className="min-w-0 p-5 xl:col-span-2">
          <SectionHeader title="Coverage trend" meta="per assessment" />
          <div className="mt-4">
            {loading ? <Skeleton className="h-36 w-full" /> : <CoverageRows trend={coverageTrend ?? null} />}
          </div>
        </div>
      </div>
    </Card>
  );
};