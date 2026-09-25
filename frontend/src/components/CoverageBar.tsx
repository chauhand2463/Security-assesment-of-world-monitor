import React from 'react';

interface CoverageBarProps {
  done: number;
  total: number;
  tone?: string;
  label?: string;
  className?: string;
}

/** Deterministic coverage bar: real done/total, never a synthesized number. */
export const CoverageBar: React.FC<CoverageBarProps> = ({
  done,
  total,
  tone = 'bg-accent',
  label,
  className,
}) => {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div className={className}>
      {label && (
        <div className="mb-1.5 flex items-center justify-between gap-3">
          <span className="text-[10px] text-faint">{label}</span>
          <span className="mono-cell text-[10px] text-faint">
            {done}/{total} · {pct}%
          </span>
        </div>
      )}
      <div className="h-2 w-full overflow-hidden rounded-full bg-surface-2">
        <div
          className={`h-full rounded-full ${tone} transition-[width] duration-700 ease-spring`}
          style={{ width: `${pct}%` }}
          aria-hidden="true"
        />
      </div>
    </div>
  );
};