import React from 'react';
import { Link } from 'react-router-dom';
import { Card } from '../Card';
import { Skeleton } from '../Skeleton';

interface MetricCardProps {
  label: string;
  icon?: React.ReactNode;
  value: number | string | null | undefined;
  note?: React.ReactNode;
  loading?: boolean;
  iconTone?: string;
  valueTone?: string;
  to?: string;
}

/**
 * Compact stat card. Consistent padding, label on top, metric in the middle,
 * note pinned to the bottom on a shared baseline across a grid row.
 */
export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  icon,
  value,
  note,
  loading,
  iconTone = 'text-accent',
  valueTone = 'text-text',
  to,
}) => {
  const body = (
    <div className="flex h-full flex-col p-5">
      <div className="flex items-center justify-between gap-3">
        <p className="eyebrow">{label}</p>
        {icon && (
          <span
            className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-line bg-surface-2 ${iconTone}`}
          >
            {icon}
          </span>
        )}
      </div>

      <div className="mt-3">
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : value === null || value === undefined ? (
          <span className="tnum block text-[26px] font-semibold leading-none tracking-tight text-faint">—</span>
        ) : (
          <span className={`tnum block text-[26px] font-semibold leading-none tracking-tight ${valueTone}`}>
            {value}
          </span>
        )}
      </div>

      {note && <p className="mono-cell mt-auto pt-3 text-[9.5px] text-faint">{note}</p>}
    </div>
  );

  if (to) {
    return (
      <Link to={to} className="block h-full no-underline">
        <Card className="h-full transition-colors duration-500 ease-spring hover:border-line-strong">{body}</Card>
      </Link>
    );
  }

  return <Card className="h-full">{body}</Card>;
};