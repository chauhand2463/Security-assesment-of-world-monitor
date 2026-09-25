import React from 'react';
import { Link } from 'react-router-dom';
import { Radar, ArrowRight } from 'lucide-react';
import { StatusBadge } from '../StatusBadge';
import { relativeTime } from '../format';

interface DashboardHeaderProps {
  assessmentsCount: number;
  latestStatus?: string | null;
  latestCreatedAt?: string | null;
}

/**
 * Top control bar: breadcrumb/context on the left, primary action on the
 * right. Actions wrap onto a second row on small screens.
 */
export const DashboardHeader: React.FC<DashboardHeaderProps> = ({
  assessmentsCount,
  latestStatus,
  latestCreatedAt,
}) => (
  <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
    <div className="min-w-0">
      <span className="chip mb-3">Operations / Overview</span>
      <h1 className="display text-[26px] font-semibold tracking-tight text-text sm:text-[30px]">
        Assessment overview
      </h1>
      <div className="mt-2.5 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2 text-[12px] leading-none text-muted">
        {latestStatus ? (
          <>
            <StatusBadge status={latestStatus} />
            <span className="text-faint" aria-hidden="true">
              ·
            </span>
          </>
        ) : null}
        <span>
          {assessmentsCount} assessment{assessmentsCount === 1 ? '' : 's'}
        </span>
        {latestCreatedAt ? (
          <>
            <span className="text-faint" aria-hidden="true">
              ·
            </span>
            <span>
              last run <span className="mono-cell text-faint">{relativeTime(latestCreatedAt)}</span>
            </span>
          </>
        ) : null}
      </div>
    </div>

    <div className="flex shrink-0 flex-wrap items-center gap-2">
      <Link
        to="/scan/new"
        className="group inline-flex items-center gap-2 rounded-full border border-accent/60 bg-accent px-5 py-2.5 text-[12.5px] font-medium text-[#04140e] no-underline transition-[background-color,box-shadow,transform] duration-500 ease-spring hover:bg-accent-bright active:scale-[0.98]"
      >
        <Radar className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
        New Assessment
        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-[#04140e]/10 transition-transform duration-500 ease-spring group-hover:translate-x-0.5">
          <ArrowRight className="h-3 w-3" strokeWidth={1.75} aria-hidden="true" />
        </span>
      </Link>
    </div>
  </div>
);