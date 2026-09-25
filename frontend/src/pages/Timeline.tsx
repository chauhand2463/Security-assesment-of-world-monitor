import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Activity,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Filter,
  History,
} from 'lucide-react';
import { getScanTimeline } from '../api';
import type { TimelineItem } from '../api';
import { PageHeader } from '../components/PageHeader';
import { EmptyState } from '../components/EmptyState';
import { SkeletonPanel } from '../components/Skeleton';
import { StatusBadge } from '../components/StatusBadge';
import { formatDateTime, relativeTime } from '../components/format';

type EventTone = 'ok' | 'warn' | 'danger' | 'accent' | 'neutral';

const toneFor = (type: string): EventTone => {
  const t = (type || '').toLowerCase();
  if (t.includes('error') || t.includes('finding') || t === 'failed') return 'danger';
  if (t.includes('validat') || t.includes('rejected') || t.includes('skipped')) return 'warn';
  if (t === 'done' || t === 'completed') return 'ok';
  if (
    t.startsWith('endpoint') ||
    t.startsWith('parameter') ||
    t.startsWith('asset') ||
    t.startsWith('observation') ||
    t.startsWith('assessment')
  )
    return 'accent';
  return 'neutral';
};

const TONE_CLASS: Record<EventTone, string> = {
  ok: 'border-accent/40 bg-accent/[0.07] text-accent',
  warn: 'border-medium/40 bg-medium/[0.07] text-medium',
  danger: 'border-critical/40 bg-critical/[0.07] text-critical',
  accent: 'border-accent/25 bg-accent/[0.04] text-accent',
  neutral: 'border-line bg-white/[0.02] text-muted',
};

type RefKey = keyof TimelineItem['reference'];

const REF_LABELS: { key: RefKey; label: string }[] = [
  { key: 'observation_id', label: 'observation' },
  { key: 'asset_id', label: 'asset' },
  { key: 'finding_id', label: 'finding' },
  { key: 'assessment_test_id', label: 'assessment test' },
  { key: 'execution_id', label: 'execution' },
  { key: 'judgment_id', label: 'judgment' },
  { key: 'verification_id', label: 'verification' },
  { key: 'id', label: 'event' },
];

export const Timeline: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const scanId = Number(id);
  const [items, setItems] = useState<TimelineItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('all');
  const [expanded, setExpanded] = useState<number | null>(null);

  const fetchTimeline = useCallback(async () => {
    setLoading(true);
    const res = await getScanTimeline(scanId);
    setItems(res?.items ?? []);
    setLoading(false);
  }, [scanId]);

  useEffect(() => {
    void fetchTimeline();
  }, [fetchTimeline]);

  const typeCounts = useMemo(() => {
    const m: Record<string, number> = {};
    items.forEach((i) => {
      m[i.type] = (m[i.type] ?? 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [items]);

  const visible = useMemo(
    () => (filter === 'all' ? items : items.filter((i) => i.type === filter)),
    [items, filter],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Assessments / Timeline"
        title="Event timeline"
        description="Persisted ScanEvent rows for this assessment — every state, stage, tool, coverage, finding and evidence event in sequence. Only persisted events are shown; nothing is synthesized."
        actions={
          <Link
            to={`/scans/${scanId}`}
            className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
          >
            <ArrowLeft className="w-3 h-3" aria-hidden="true" />
            Assessment detail
          </Link>
        }
      />

      <div className="flex items-start gap-2.5 rounded-2xl border border-line bg-surface-2/60 p-3.5">
        <History className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" strokeWidth={1.5} aria-hidden="true" />
        <p className="text-[11px] leading-relaxed text-muted">
          Events come from the persisted `ScanEvent` ledger — state/stage transitions, tool runs, coverage updates,
          endpoint and parameter discovery, observations, findings and validation. Reference chips link each event to the
          persisted record it belongs to (observation, asset, finding, assessment test, execution, judgment, verification).
        </p>
      </div>

      {loading ? (
        <div className="space-y-4">
          <SkeletonPanel className="min-h-[220px]" />
          <SkeletonPanel className="min-h-[380px]" />
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={<Activity className="h-4 w-4" aria-hidden="true" />}
          title="No persisted events"
          description="This assessment has not recorded any ScanEvent rows yet."
        />
      ) : (
        <>
          <section className="panel p-5">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Filter className="h-3.5 w-3.5 text-faint" strokeWidth={1.5} aria-hidden="true" />
              <button
                type="button"
                onClick={() => setFilter('all')}
                className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[10px] transition-colors duration-500 ease-spring ${
                  filter === 'all' ? 'border-accent/60 text-accent bg-accent/10' : 'border-line text-faint hover:text-muted'
                }`}
              >
                all ({items.length})
              </button>
              {typeCounts.map(([type, count]) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setFilter(type)}
                  className={`mono-cell cursor-pointer rounded-full border px-2.5 py-0.5 text-[10px] transition-colors duration-500 ease-spring ${
                    filter === type ? 'border-accent/60 text-accent bg-accent/10' : 'border-line text-faint hover:text-muted'
                  }`}
                >
                  {type} ({count})
                </button>
              ))}
            </div>
            <p className="mono-cell text-[10px] text-faint">{visible.length} events shown · ordered by persisted id</p>
          </section>

          <section className="panel overflow-hidden">
            <ol className="mx-5 my-5 space-y-1.5 border-l border-line/70 pl-5">
              {visible.map((item) => {
                const tone = toneFor(item.type);
                const isOpen = expanded === item.id;
                const hasPayload = Object.keys(item.data ?? {}).length > 0;
                return (
                  <li key={item.id} className="relative">
                    <span
                      className={`absolute -left-[27px] top-[15px] h-2 w-2 rounded-full border ${
                        tone === 'ok'
                          ? 'border-accent bg-accent'
                          : tone === 'danger'
                          ? 'border-critical bg-critical'
                          : tone === 'warn'
                          ? 'border-medium bg-medium'
                          : 'border-line-strong bg-surface-2'
                      }`}
                      aria-hidden="true"
                    />
                    <div className="group rounded-xl border border-line bg-surface-2/50 px-3.5 py-3 transition-colors duration-500 ease-spring hover:border-line-strong">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                        <span className={`mono-cell shrink-0 rounded-md border px-2 py-0.5 text-[9.5px] ${TONE_CLASS[tone]}`}>
                          {item.type}
                        </span>
                        <span className="mono-cell shrink-0 text-[9px] text-faint">#{item.id}</span>
                        {item.source && (
                          <span className="mono-cell shrink-0 rounded-md border border-line px-1.5 py-0.5 text-[9.5px] text-muted">
                            {item.source}
                          </span>
                        )}
                        {item.status && <StatusBadge status={item.status} />}
                        <span className="mono-cell ml-auto shrink-0 text-[9.5px] text-faint" title={formatDateTime(item.created_at)}>
                          {relativeTime(item.created_at)}
                        </span>
                      </div>
                      {item.target && (
                        <p className="mt-2 break-all font-mono text-[10.5px] leading-relaxed text-text [overflow-wrap:anywhere]">
                          {item.target}
                        </p>
                      )}
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        {REF_LABELS.filter(({ key }) => item.reference?.[key]).map(({ key, label }) => (
                          <span
                            key={key}
                            className="mono-cell rounded-md border border-accent/20 bg-accent/[0.03] px-1.5 py-0.5 text-[9px] text-accent"
                          >
                            {label} #{item.reference[key]}
                          </span>
                        ))}
                        {hasPayload && (
                          <button
                            type="button"
                            onClick={() => setExpanded(isOpen ? null : item.id)}
                            className="mono-cell ml-auto inline-flex cursor-pointer items-center gap-1 rounded-full border border-line px-2 py-0.5 text-[9.5px] text-faint transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text"
                            aria-expanded={isOpen}
                          >
                            {isOpen ? (
                              <ChevronDown className="h-3 w-3" strokeWidth={1.5} aria-hidden="true" />
                            ) : (
                              <ChevronRight className="h-3 w-3" strokeWidth={1.5} aria-hidden="true" />
                            )}
                            payload
                          </button>
                        )}
                      </div>
                      {isOpen && hasPayload && (
                        <pre className="scrollbar-thin mt-3 max-h-72 overflow-auto whitespace-pre-wrap rounded-xl border border-line bg-[#0a0a0c] p-3 font-mono text-[9.5px] leading-relaxed text-muted [overflow-wrap:anywhere]">
                          {JSON.stringify(item.data, null, 2)}
                        </pre>
                      )}
                    </div>
                  </li>
                );
              })}
            </ol>
          </section>
        </>
      )}
    </div>
  );
};

export default Timeline;