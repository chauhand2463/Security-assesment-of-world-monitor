import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { EmptyState } from '../EmptyState';
import { Skeleton } from '../Skeleton';

interface ScoreDatum {
  target?: string;
  score?: number | null;
  created_at?: string | null;
  id?: number;
}

export const SecurityScoreTrend: React.FC<{ history: ScoreDatum[] | null; loading: boolean }> = ({ history, loading }) => {
  if (loading) {
    return <Skeleton className="h-36 w-full" />;
  }

  const rows = [...(history ?? [])].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at))).slice(-8);

  if (rows.length === 0) {
    return (
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
    );
  }

  return (
    <div className="flex h-36 items-end gap-2">
      {rows.map((h) => {
        const score = h.score == null ? null : Math.max(0, Math.min(100, Number(h.score)));
        const label = (h.target ?? '').split('.').slice(0, 1)[0] || '—';
        return (
          <div key={h.id ?? label} className="flex min-w-0 flex-1 flex-col items-center gap-1.5">
            <span className="mono-cell text-[9px] text-faint">{score == null ? '—' : Math.round(score)}</span>
            <div className="flex h-[6.5rem] w-full items-end overflow-hidden rounded-lg bg-surface-2">
              <div
                className={`w-full rounded-lg transition-[height] duration-700 ease-spring ${
                  score == null ? 'bg-white/[0.04]' : 'bg-gradient-to-t from-accent/55 to-accent'
                }`}
                style={{ height: score == null ? '4%' : `${Math.max(4, score)}%` }}
              />
            </div>
            <span className="mono-cell w-full truncate text-center text-[8px] text-faint">{label}</span>
          </div>
        );
      })}
    </div>
  );
};