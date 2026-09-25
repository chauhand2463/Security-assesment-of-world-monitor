import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ChevronDown } from 'lucide-react';
import { getScanList } from '../api';
import type { ScanRow } from '../api';
import { Skeleton } from './Skeleton';

interface ScanPickerProps {
  value: number | null;
  onChange: (scanId: number | null) => void;
  disabled?: boolean;
}

/** Dropdown of the user's assessments (newest first) for scan-scoped pages. */
export const ScanPicker: React.FC<ScanPickerProps> = ({ value, onChange, disabled }) => {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchParams] = useSearchParams();

  useEffect(() => {
    let alive = true;
    void getScanList().then((rows) => {
      if (!alive) return;
      const list = rows ?? [];
      setScans([...list].sort((a, b) => b.id - a.id));
      const param = searchParams.get('scan');
      const preferred = param ? Number(param) : null;
      const has = list.some((s) => s.id === value);
      if (!has) {
        const pick = preferred && list.some((s) => s.id === preferred)
          ? preferred
          : list.length > 0
          ? list[0].id
          : null;
        onChange(pick);
      }
    }).finally(() => {
      if (alive) setLoading(false);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) {
    return <Skeleton className="h-8 w-60 rounded-full" />;
  }
  if (scans.length === 0) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11.5px] text-faint">
        No assessments yet
      </span>
    );
  }

  return (
    <label className="relative inline-flex items-center">
      <span className="absolute left-3 text-[10px] uppercase tracking-wider text-faint pointer-events-none">
        Assessment
      </span>
      <select
        value={value ?? ''}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
        aria-busy={loading}
        className="h-9 cursor-pointer appearance-none rounded-full border border-line bg-surface-2 py-1.5 pl-24 pr-9 text-[11.5px] text-text outline-none transition-[border-color,background-color] duration-500 ease-spring hover:border-line-strong focus:border-accent disabled:opacity-50"
        aria-label="Select assessment"
      >
        <option value="" disabled>
          Select an assessment
        </option>
        {scans.map((s) => (
          <option key={s.id} value={s.id}>
            #{s.id} · {s.target} · {s.status}
          </option>
        ))}
      </select>
      <ChevronDown
        className="pointer-events-none absolute right-3 h-3.5 w-3.5 text-faint"
        strokeWidth={1.5}
        aria-hidden="true"
      />
    </label>
  );
};