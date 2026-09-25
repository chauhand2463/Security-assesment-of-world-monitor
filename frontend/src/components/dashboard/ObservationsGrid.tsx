import React from 'react';
import { Link } from 'react-router-dom';
import { Layers } from 'lucide-react';
import { Card } from '../Card';
import { SectionHeader } from '../SectionHeader';
import { Skeleton } from '../Skeleton';
import { EmptyState } from '../EmptyState';

interface ScanRef {
  id: number;
  target: string;
}

interface ObservationsGridProps {
  byScan: Record<string, number> | null | undefined;
  scans: ScanRef[];
  observationCount: number | null | undefined;
  assetsTotal: number | null | undefined;
  loading: boolean;
}

const entryCount = (v: number | null | undefined): string => {
  if (v === null || v === undefined) return '—';
  return String(v);
};

export const ObservationsGrid: React.FC<ObservationsGridProps> = ({
  byScan,
  scans,
  observationCount,
  assetsTotal,
  loading,
}) => {
  const entries = Object.entries(byScan ?? {})
    .map(([scanId, count]) => ({
      scanId: Number(scanId),
      count,
      target: scans.find((s) => String(s.id) === String(scanId))?.target,
    }))
    .sort((a, b) => b.count - a.count);

  const meta = `${entryCount(observationCount)} persisted · ${entryCount(assetsTotal)} assets`;

  return (
    <Card className="overflow-hidden">
      <SectionHeader
        title="Observations (evidence chain)"
        icon={<Layers className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />}
        meta={meta}
        className="px-5 pt-5 pb-4"
      />
      <div className="px-5 pb-5">
        {loading ? (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-24 rounded-xl" />
            ))}
          </div>
        ) : entries.length === 0 ? (
          <EmptyState
            title="No observations persisted"
            description="Run a real assessment; every observation is stored before any finding is derived."
          />
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {entries.map((entry) => (
              <Link key={entry.scanId} to={`/scans/${entry.scanId}`} className="block no-underline">
                <Card className="flex h-full flex-col p-5 transition-colors duration-500 ease-spring hover:border-line-strong">
                  <p className="mono-cell text-[9.5px] uppercase tracking-[0.14em] text-faint">
                    assessment #{entry.scanId}
                  </p>
                  <p className="mt-1 truncate text-[11.5px] font-medium text-text">
                    {entry.target ? entry.target : `#${entry.scanId}`}
                  </p>
                  <p className="tnum mt-4 text-[26px] font-semibold leading-none tracking-tight text-text">
                    {entry.count}
                  </p>
                  <p className="mono-cell mt-auto pt-2 text-[9.5px] text-faint">
                    {entry.count === 1 ? 'observation persisted' : 'observations persisted'}
                  </p>
                </Card>
              </Link>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
};