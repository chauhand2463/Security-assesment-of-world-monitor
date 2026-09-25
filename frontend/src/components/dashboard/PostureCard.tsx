import React from 'react';
import { Link } from 'react-router-dom';
import { Skeleton } from '../Skeleton';
import { Card } from '../Card';
import { SectionHeader } from '../SectionHeader';
import { ShieldCheck } from 'lucide-react';

interface PostureMetricProps {
  label: string;
  value: number | null | undefined;
  note: string;
  accent?: boolean;
  to: string;
  loading: boolean;
}

const PostureMetric: React.FC<PostureMetricProps> = ({ label, value, note, accent, to, loading }) => (
  <Link to={to} className="group block min-w-0 no-underline">
    <p className="eyebrow">{label}</p>
    <div className="mt-1.5 flex items-baseline gap-1.5">
      {loading ? (
        <Skeleton className="h-7 w-16" />
      ) : value === null || value === undefined ? (
        <span
          className={`tnum text-[22px] font-semibold leading-none tracking-tight ${accent ? 'text-accent' : 'text-faint'}`}
        >
          —
        </span>
      ) : (
        <span
          className={`tnum text-[22px] font-semibold leading-none tracking-tight transition-colors duration-500 ease-spring ${
            accent ? 'text-accent' : 'text-text'
          }`}
        >
          {value}
        </span>
      )}
    </div>
    <p className="mono-cell mt-1.5 text-[9.5px] text-faint">{note}</p>
  </Link>
);

interface PostureCardProps {
  confirmedFindings: number | null | undefined;
  candidateFindings: number | null | undefined;
  observationCount: number | null | undefined;
  assetsTotal: number | null | undefined;
  assessmentsTotal: number | null | undefined;
  loading: boolean;
  className?: string;
}

/**
 * Evidence-backed posture panel. The dominant card in the summary row; its
 * four internal statistics derive only from the persisted backend aggregate.
 */
export const PostureCard: React.FC<PostureCardProps> = ({
  confirmedFindings,
  candidateFindings,
  observationCount,
  assetsTotal,
  assessmentsTotal,
  loading,
  className = '',
}) => (
  <Card className={`flex h-full flex-col ${className}`}>
    <SectionHeader
      title="Evidence-backed posture"
      icon={<ShieldCheck className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />}
      meta="persisted records only"
      className="px-5 pt-5 pb-4"
    />
    <div className="flex flex-1 flex-col px-5 pb-4">
      <div className="grid grid-cols-2 gap-x-5 gap-y-5 sm:grid-cols-4 xl:grid-cols-2">
        <PostureMetric
          label="Confirmed findings"
          value={confirmedFindings}
          note="evidence-validated"
          accent
          to="/findings"
          loading={loading}
        />
        <PostureMetric
          label="Candidates"
          value={candidateFindings}
          note="awaiting verification"
          to="/findings"
          loading={loading}
        />
        <PostureMetric
          label="Evidence records"
          value={observationCount}
          note="persisted observations"
          to="/coverage"
          loading={loading}
        />
        <PostureMetric label="Assets in scope" value={assetsTotal} note="discovered assets" to="/assets" loading={loading} />
      </div>

      <p className="mt-auto border-t border-line pt-3 text-[10.5px] leading-relaxed text-faint">
        Confirmed findings are validated against deterministic evidence; candidates await verification. Every
        observation is stored before any finding is derived — totals come straight from the backend aggregate
        {assessmentsTotal && assessmentsTotal > 0 ? ` (${assessmentsTotal} assessment${assessmentsTotal === 1 ? '' : 's'} on record)` : ''}.
      </p>
    </div>
  </Card>
);