import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, ExternalLink } from 'lucide-react';
import { Card } from '../Card';
import { SectionHeader } from '../SectionHeader';
import { EmptyState } from '../EmptyState';
import { ErrorState } from '../ErrorState';
import { Skeleton } from '../Skeleton';
import { DataTable } from '../DataTable';
import { StatusBadge } from '../StatusBadge';
import { relativeTime } from '../format';

export interface RecentScanRow {
  id: number;
  target: string;
  status: string;
  security_score: number | null;
  coverage: number | null;
  observations: number | null;
  created_at: string | null;
}

interface RecentAssessmentsProps {
  rows: RecentScanRow[];
  rowCount: number;
  loading: boolean;
  error: string;
  onRetry: () => void;
}

export const RecentAssessments: React.FC<RecentAssessmentsProps> = ({ rows, rowCount, loading, error, onRetry }) => {
  const navigate = useNavigate();

  const columns = [
    {
      key: 'target',
      label: 'Target',
      render: (s: RecentScanRow) => <span className="font-medium text-text">{s.target}</span>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (s: RecentScanRow) => <StatusBadge status={s.status} />,
    },
    {
      key: 'score',
      label: 'Score',
      className: 'text-right',
      headerClassName: 'text-right',
      render: (s: RecentScanRow) => (
        <span className="mono-cell text-muted">{s.security_score != null ? `${s.security_score}/100` : '—'}</span>
      ),
    },
    {
      key: 'coverage',
      label: 'Coverage',
      className: 'text-right',
      headerClassName: 'text-right',
      render: (s: RecentScanRow) => (
        <span className="mono-cell text-muted">{s.coverage != null ? `${s.coverage}%` : '—'}</span>
      ),
    },
    {
      key: 'evidence',
      label: 'Evidence',
      className: 'text-right',
      headerClassName: 'text-right',
      render: (s: RecentScanRow) => (
        <span className="mono-cell text-[10.5px] text-faint">
          {s.observations === null || s.observations === undefined ? '—' : `${s.observations} obs`}
        </span>
      ),
    },
    {
      key: 'created',
      label: 'Triggered',
      render: (s: RecentScanRow) => <span className="text-[11px] text-faint">{relativeTime(s.created_at)}</span>,
    },
    {
      key: 'action',
      label: 'Action',
      className: 'text-right',
      headerClassName: 'text-right',
      render: (s: RecentScanRow) => (
        <Link
          to={`/scans/${s.id}`}
          className="group inline-flex items-center gap-1 text-[11.5px] font-medium text-accent no-underline transition-colors duration-500 ease-spring hover:text-accent-bright"
          aria-label={`Open assessment #${s.id}`}
        >
          View
          <ExternalLink className="h-3 w-3" strokeWidth={1.75} aria-hidden="true" />
        </Link>
      ),
    },
  ];

  return (
    <Card className="overflow-hidden">
      <SectionHeader
        title="Recent assessments"
        meta={`${rowCount} on record`}
        actions={
          <Link
            to="/scans"
            className="group inline-flex items-center gap-1 text-[11.5px] font-medium text-accent no-underline transition-colors duration-500 ease-spring hover:text-accent-bright"
          >
            View all
            <ArrowRight
              className="h-3 w-3 transition-transform duration-500 ease-spring group-hover:translate-x-0.5"
              strokeWidth={1.75}
              aria-hidden="true"
            />
          </Link>
        }
        className="px-5 pt-5 pb-4"
      />
      <div className="min-w-0">
        {error ? (
          <div className="px-5 pb-5">
            <ErrorState message={error} onRetry={onRetry} />
          </div>
        ) : loading ? (
          <div>
            <div className="grid grid-cols-7 gap-4 border-y border-line bg-white/[0.015] px-5 py-3.5">
              {Array.from({ length: 7 }).map((_, i) => (
                <Skeleton key={i} className="h-3" />
              ))}
            </div>
            {Array.from({ length: 3 }).map((_, r) => (
              <div key={r} className="grid grid-cols-7 gap-4 border-b border-line/60 px-5 py-4 last:border-b-0">
                {Array.from({ length: 7 }).map((_, c) => (
                  <Skeleton key={c} className="h-3" />
                ))}
              </div>
            ))}
          </div>
        ) : rows.length === 0 ? (
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
            columns={columns}
            rows={rows}
            keyField={(s: RecentScanRow) => String(s.id)}
            bordered={false}
            onRowClick={(s: RecentScanRow) => navigate(`/scans/${s.id}`)}
          />
        )}
      </div>
    </Card>
  );
};