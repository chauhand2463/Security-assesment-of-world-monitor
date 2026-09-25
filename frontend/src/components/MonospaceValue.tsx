import React from 'react';
import { CopyButton } from './CopyButton';

interface MonospaceValueProps {
  value: string;
  copyable?: boolean;
  className?: string;
  copyLabel?: string;
}

/** Long-safe monospace token (URLs, fingerprints, ids) that never overflows. */
export const MonospaceValue: React.FC<MonospaceValueProps> = ({
  value,
  copyable,
  className,
  copyLabel,
}) => (
  <span className="minw-0 inline-flex max-w-full items-center gap-2">
    <span className={`wrap-any mono-cell min-w-0 ${className ?? 'text-[11px] text-text'}`}>{value}</span>
    {copyable && <CopyButton value={value} label={copyLabel} />}
  </span>
);