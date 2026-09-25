import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Crosshair } from 'lucide-react';
import { Card } from '../Card';
import { SectionHeader } from '../SectionHeader';
import { Skeleton } from '../Skeleton';
import { EmptyState } from '../EmptyState';
import type { SurfaceCoverage } from '../../api';

const MiniStat: React.FC<{ label: string; done: number; total: number; tone: string }> = ({
  label,
  done,
  total,
  tone,
}) => {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div className="flex min-w-0 flex-col rounded-xl border border-line bg-surface-2/60 px-4 py-3">
      <div className="flex items-baseline justify-between gap-2">
        <p className="truncate text-[11.5px] font-medium text-text">{label}</p>
        <p className="mono-cell shrink-0 text-[10px] text-faint">
          {done}/{total}
        </p>
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-surface-2" role="presentation">
        <div className={`h-full rounded-full ${tone} transition-[width] duration-700 ease-spring`} style={{ width: `${pct}%` }} />
      </div>
      <p className="mono-cell mt-1 text-[9.5px] text-faint">
        {total > 0 ? `${pct}% of observed surface covered` : 'nothing observed'}
      </p>
    </div>
  );
};

interface SurfaceCardProps {
  latestScanId: number | null;
  surface: SurfaceCoverage | null;
  loading: boolean;
}

export const SurfaceCard: React.FC<SurfaceCardProps> = ({ latestScanId, surface, loading }) => (
  <Card className="flex h-full flex-col">
    <SectionHeader
      title="Latest observed surface"
      icon={<Crosshair className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />}
      meta={latestScanId == null ? 'assessment #—' : `assessment #${latestScanId}`}
      actions={
        latestScanId != null ? (
          <Link
            to={`/coverage?scan=${latestScanId}`}
            className="group inline-flex items-center gap-1 text-[11.5px] font-medium text-accent no-underline transition-colors duration-500 ease-spring hover:text-accent-bright"
          >
            Full coverage
            <ArrowRight
              className="h-3 w-3 transition-transform duration-500 ease-spring group-hover:translate-x-0.5"
              strokeWidth={1.75}
              aria-hidden="true"
            />
          </Link>
        ) : undefined
      }
      className="px-5 pt-5 pb-4"
    />
    <div className="flex flex-1 flex-col px-5 pb-5">
      {loading ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {Array.from({ length: 2 }).map((_, i) => (
            <Skeleton key={i} className="h-16 rounded-xl" />
          ))}
        </div>
      ) : surface == null ? (
        <EmptyState
          title="No observed surface yet"
          description="Run an assessment and endpoints/parameters will show here from persisted evidence."
        />
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <MiniStat label="Endpoints assessed" done={surface.endpoints_assessed} total={surface.endpoints_total} tone="bg-accent" />
          <MiniStat label="Parameters assessed" done={surface.parameters_assessed} total={surface.parameters_total} tone="bg-high" />
        </div>
      )}
    </div>
  </Card>
);