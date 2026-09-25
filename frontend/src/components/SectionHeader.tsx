import React from 'react';

interface SectionHeaderProps {
  title: string;
  icon?: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}

/** Consistent panel section heading: icon label, optional meta + actions. */
export const SectionHeader: React.FC<SectionHeaderProps> = ({
  title,
  icon,
  meta,
  actions,
  className,
}) => (
  <div className={`flex flex-wrap items-center justify-between gap-3 ${className ?? ''}`}>
    <h2 className="flex min-w-0 items-center gap-2 text-[12.5px] font-semibold text-text">
      {icon && <span className="shrink-0 text-accent">{icon}</span>}
      <span className="truncate">{title}</span>
    </h2>
    {meta && <span className="mono-cell text-[10px] text-faint">{meta}</span>}
    {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
  </div>
);