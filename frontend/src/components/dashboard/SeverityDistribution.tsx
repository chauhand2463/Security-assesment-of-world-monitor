import React from 'react';
import { EmptyState } from '../EmptyState';
import { Skeleton } from '../Skeleton';
import { SeverityText } from '../SeverityBadge';

const ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

function sevColorClass(sev: string): string {
  switch (sev) {
    case 'Critical':
      return 'bg-critical';
    case 'High':
      return 'bg-high';
    case 'Medium':
      return 'bg-medium';
    case 'Low':
      return 'bg-low';
    default:
      return 'bg-faint';
  }
}

export const SeverityDistribution: React.FC<{ dist: Record<string, number> | null | undefined; loading: boolean }> = ({
  dist,
  loading,
}) => {
  if (loading) {
    return <Skeleton className="h-36 w-full" />;
  }

  const rows = ORDER.filter((sev) => (dist?.[sev] ?? 0) > 0);
  const total = Object.values(dist ?? {}).reduce((a, b) => a + b, 0);
  const max = Math.max(1, ...Object.values(dist ?? {}));

  if (rows.length === 0 || total === 0) {
    return (
      <EmptyState
        title="No open findings"
        description="Findings appear here once evidence-backed records are persisted for an assessment."
      />
    );
  }

  return (
    <div className="flex flex-col justify-center gap-3">
      {rows.map((sev) => {
        const count = dist?.[sev] ?? 0;
        return (
          <div key={sev} className="flex items-center gap-2.5">
            <span className="w-16 shrink-0">
              <SeverityText severity={sev} />
            </span>
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
              <div
                className={`h-full rounded-full ${sevColorClass(sev)} transition-[width] duration-700 ease-spring`}
                style={{ width: `${Math.max(3, (count / max) * 100)}%` }}
              />
            </div>
            <span className="mono-cell w-7 shrink-0 text-right text-faint">{count}</span>
          </div>
        );
      })}
    </div>
  );
};