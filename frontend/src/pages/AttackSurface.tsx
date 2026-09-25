import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Radar,
  FileJson,
  FileCode2,
  Fingerprint,
  Globe,
  ShieldCheck,
  Lock,
  ScanSearch,
  Database,
  Filter,
  Zap,
} from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  motion,
  AnimatePresence,
  useReducedMotion,
  useMotionValue,
  useTransform,
  animate,
  useInView,
} from 'framer-motion';
import { apiResult } from '../api';
import type { SurfaceSnapshot, SurfaceEndpoint, SurfaceParameter } from '../api';
import { PageHeader } from '../components/PageHeader';
import { ScanPicker } from '../components/ScanPicker';
import { DataTable } from '../components/DataTable';
import { EmptyState } from '../components/EmptyState';
import { SkeletonTable, SkeletonPanel } from '../components/Skeleton';
import { StatusBadge } from '../components/StatusBadge';
import { SectionHeader } from '../components/SectionHeader';
import { CoverageBar } from '../components/CoverageBar';
import { DetailDrawer } from '../components/DetailDrawer';
import { CopyButton } from '../components/CopyButton';
import { MonospaceValue } from '../components/MonospaceValue';
import { UrlValue } from '../components/UrlValue';
import { relativeTime, formatDateTime } from '../components/format';

/* ─── Stagger presets ─── */
const stagger = {
  hidden: {},
  show: { transition: { staggerChildren: 0.06, delayChildren: 0.08 } },
};
const fadeUp = {
  hidden: { opacity: 0, y: 18 },
  show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] } },
};
const fadeIn = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] } },
};
const scaleIn = {
  hidden: { opacity: 0, scale: 0.92 },
  show: { opacity: 1, scale: 1, transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] } },
};

/* ─── Animated counter hook ─── */
function useAnimatedCounter(target: number, duration = 1.2) {
  const motionVal = useMotionValue(0);
  const rounded = useTransform(motionVal, (v) => Math.round(v));
  const [display, setDisplay] = useState(0);
  const ref = useRef<HTMLParagraphElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-40px' });
  const reduce = useReducedMotion();

  useEffect(() => {
    if (!isInView) return;
    if (reduce) {
      setDisplay(target);
      return;
    }
    const controls = animate(motionVal, target, {
      duration,
      ease: [0.22, 1, 0.36, 1],
    });
    const unsub = rounded.on('change', (v) => setDisplay(v));
    return () => {
      controls.stop();
      unsub();
    };
  }, [target, isInView, reduce, motionVal, rounded, duration]);

  return { display, ref };
}

export const AttackSurface: React.FC = () => {
  const [scanId, setScanId] = useState<number | null>(null);
  const [surface, setSurface] = useState<SurfaceSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchParams, setSearchParams] = useSearchParams();

  const [schemeFilter, setSchemeFilter] = useState<string>('all');
  const [assessedFilter, setAssessedFilter] = useState<'all' | 'assessed' | 'unassessed'>('all');

  const [selectedEndpoint, setSelectedEndpoint] = useState<SurfaceEndpoint | null>(null);
  const [selectedParameter, setSelectedParameter] = useState<SurfaceParameter | null>(null);
  const [lastEndpoint, setLastEndpoint] = useState<SurfaceEndpoint | null>(null);
  const [lastParameter, setLastParameter] = useState<SurfaceParameter | null>(null);

  const reduce = useReducedMotion();

  useEffect(() => {
    if (selectedEndpoint) setLastEndpoint(selectedEndpoint);
  }, [selectedEndpoint]);

  useEffect(() => {
    if (selectedParameter) setLastParameter(selectedParameter);
  }, [selectedParameter]);

  const activeEndpoint = selectedEndpoint || lastEndpoint;
  const activeParameter = selectedParameter || lastParameter;

  const deepLinkRef = useRef<string | null>(searchParams.get('endpoint'));

  const fetchSurface = useCallback(async (id: number) => {
    setLoading(true);
    setSurface(null);
    setError(null);
    setSelectedEndpoint(null);
    setSelectedParameter(null);
    const result = await apiResult<SurfaceSnapshot>(`/scans/${id}/surface`);
    if (!result.ok) {
      setError(result.error.kind === 'http' ? 'Surface unavailable for this assessment.' : result.error.message);
      setLoading(false);
      return;
    }
    setSurface(result.data);
    setLoading(false);

    const endpointParam = deepLinkRef.current;
    if (endpointParam) {
      const url = decodeURIComponent(endpointParam);
      const match = result.data.endpoints.find((e) => e.url === url);
      if (match) setSelectedEndpoint(match);
    }
  }, []);

  useEffect(() => {
    if (scanId === null) return;
    void fetchSurface(scanId);
  }, [scanId, fetchSurface]);

  const ctx = surface?.context;

  const schemes = useMemo(() => {
    const list = new Set<string>();
    surface?.endpoints.forEach((e) => list.add(e.scheme));
    surface?.parameters.forEach((p) => {
      const scheme = p.endpoint.split('://')[0];
      list.add(scheme);
    });
    return ['all', ...Array.from(list).sort()];
  }, [surface]);

  const filteredEndpoints = useMemo(() => {
    if (!surface) return [];
    return surface.endpoints.filter((e) => {
      if (schemeFilter !== 'all' && e.scheme !== schemeFilter) return false;
      if (assessedFilter === 'assessed' && !e.assessed) return false;
      if (assessedFilter === 'unassessed' && e.assessed) return false;
      return true;
    });
  }, [surface, schemeFilter, assessedFilter]);

  const filteredParameters = useMemo(() => {
    if (!surface) return [];
    return surface.parameters.filter((p) => {
      const scheme = p.endpoint.split('://')[0];
      if (schemeFilter !== 'all' && scheme !== schemeFilter) return false;
      if (assessedFilter === 'assessed' && !p.assessed) return false;
      if (assessedFilter === 'unassessed' && p.assessed) return false;
      return true;
    });
  }, [surface, schemeFilter, assessedFilter]);

  const parametersFor = useCallback(
    (endpoint: string) => (surface?.parameters ?? []).filter((p) => p.endpoint === endpoint),
    [surface],
  );

  const openEndpoint = useCallback(
    (e: SurfaceEndpoint) => {
      setSelectedParameter(null);
      setSelectedEndpoint(e);
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set('endpoint', encodeURIComponent(e.url));
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const closeEndpoint = useCallback(() => {
    setSelectedEndpoint(null);
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete('endpoint');
        return next;
      },
      { replace: true },
    );
  }, [setSearchParams]);

  const borderTone = (e: SurfaceEndpoint) =>
    e.assessed ? 'border-accent/25 bg-accent/[0.03]' : 'border-line bg-surface-2/60';

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Inventory / Attack Surface"
        title="Attack surface"
        description="Observed endpoints, ports, parameters, hosts and discovery assets for one assessment. Every row traces back to a persisted observation — ports are explicit or scheme-defaulted, assessment markers reflect executed/validated/failed tests only, and parameter values are never surfaced."
        actions={<ScanPicker value={scanId} onChange={setScanId} />}
      />

      {scanId === null ? (
        <EmptyState
          icon={<Radar className="h-4 w-4" aria-hidden="true" />}
          title="No assessments to inspect"
          description="Run an assessment first — its observed surface (endpoints, parameters, hosts) will appear here from real persisted evidence."
          action={
            <Link to="/scan/new" className="no-underline">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3.5 py-1.5 text-[11.5px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20">
                Queue an assessment
              </span>
            </Link>
          }
        />
      ) : loading && !surface ? (
        <motion.div
          className="space-y-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <SkeletonTable rows={3} cols={4} />
          <SkeletonPanel className="min-h-[220px]" />
        </motion.div>
      ) : error && !surface ? (
        <motion.div
          className="rounded-2xl border border-critical/25 bg-critical/[0.05] px-5 py-8 text-center text-[12px] text-critical"
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4 }}
        >
          {error}
        </motion.div>
      ) : !surface ? (
        <EmptyState
          icon={<Radar className="h-4 w-4" aria-hidden="true" />}
          title="No surface recorded"
          description="This assessment has no persisted observations yet, so no surface can be shown."
        />
      ) : (
        <>
          {/* ── Observation notice ── */}
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }}
            className="group flex items-start gap-2.5 rounded-2xl border border-line bg-surface-2/60 p-3.5 transition-colors duration-500 hover:border-accent/20 hover:bg-accent/[0.02]"
          >
            <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent transition-transform duration-500 group-hover:scale-110" strokeWidth={1.5} aria-hidden="true" />
            <p className="text-[11px] leading-relaxed text-muted">
              Observation-based only. Methods are never inferred from URLs and parameter values / credential
              material are never surfaced — you see names, existence shapes, and provenance.
            </p>
          </motion.div>

          {/* ── Stats tiles ── */}
          <div className="relative grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            {/* Subtle radar sweep behind tiles */}
            {!reduce && (
              <div
                className="pointer-events-none absolute -inset-6 -z-10 opacity-30"
                aria-hidden="true"
              >
                <div className="radar-sweep absolute inset-0 rounded-full" />
              </div>
            )}
            <AnimatedTile icon={<ScanSearch className="h-3 w-3" />} label="Endpoints observed" value={surface.endpoint_count} index={0} />
            <AnimatedTile icon={<ShieldCheck className="h-3 w-3" />} label="Endpoints assessed" value={surface.coverage.endpoints_assessed} accent index={1} />
            <AnimatedTile icon={<Fingerprint className="h-3 w-3" />} label="Parameters observed" value={surface.parameter_count} index={2} />
            <AnimatedTile icon={<Globe className="h-3 w-3" />} label="Hosts observed" value={ctx?.host_count ?? 0} index={3} />
            <AnimatedTile icon={<Zap className="h-3 w-3" />} label="Discovery assets" value={surface.api_documents.length + surface.script_assets.length} index={4} />
          </div>

          {/* ── Coverage section ── */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <motion.section
              initial={{ opacity: 0, scale: 0.92 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }}
              className="panel group relative overflow-hidden p-5"
            >
              <div className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-accent/[0.04] via-transparent to-transparent opacity-0 transition-opacity duration-700 group-hover:opacity-100" />
              <SectionHeader
                title="Endpoint coverage"
                icon={<ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />}
                meta={`${surface.coverage.endpoints_assessed}/${surface.coverage.endpoints_total} assessed`}
              />
              <div className="mt-3">
                <AnimatedCoverageBar
                  done={surface.coverage.endpoints_assessed}
                  total={surface.coverage.endpoints_total}
                  tone="accent"
                />
              </div>
              <p className="mt-2.5 text-[10px] leading-relaxed text-faint">{surface.coverage.note}</p>
            </motion.section>
            <motion.section
              initial={{ opacity: 0, scale: 0.92 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number], delay: 0.08 }}
              className="panel group relative overflow-hidden p-5"
            >
              <div className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-high/[0.04] via-transparent to-transparent opacity-0 transition-opacity duration-700 group-hover:opacity-100" />
              <SectionHeader
                title="Parameter coverage"
                icon={<Fingerprint className="h-3.5 w-3.5" aria-hidden="true" />}
                meta={`${surface.coverage.parameters_assessed}/${surface.coverage.parameters_total} assessed`}
              />
              <div className="mt-3">
                <AnimatedCoverageBar
                  done={surface.coverage.parameters_assessed}
                  total={surface.coverage.parameters_total}
                  tone="high"
                />
              </div>
              <p className="mt-2.5 text-[10px] leading-relaxed text-faint">
                Assessed where the owning endpoint has executed/validated/failed assessment tests.
              </p>
            </motion.section>
          </div>

          {/* ── Context ── */}
          <motion.section
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-40px' }}
            transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }}
            className="panel overflow-hidden"
          >
            <div className="px-5 pt-5 pb-3">
              <SectionHeader
                title="Observed context"
                icon={<Globe className="h-3.5 w-3.5" aria-hidden="true" />}
                meta={`${ctx?.http_subjects ?? 0} HTTP subjects · ${ctx?.observation_count ?? 0} observations · ${ctx?.sources?.length ?? 0} sources`}
              />
            </div>
            <div className="px-5 pb-5">
              {!ctx || ctx.hosts.length === 0 ? (
                <p className="text-[11px] text-faint">No host context persisted for this assessment.</p>
              ) : (
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
                  {ctx.hosts.slice(0, 24).map((h, i) => (
                    <HostCard key={h.host} host={h} index={i} />
                  ))}
                </div>
              )}
            </div>
          </motion.section>

          {/* ── Filter toolbar ── */}
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, margin: '-20px' }}
            transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }}
            className="flex flex-wrap items-center gap-2.5"
          >
            <Filter className="h-3.5 w-3.5 text-faint" strokeWidth={1.5} aria-hidden="true" />
            <label className="flex items-center gap-2 text-[10.5px] text-faint">
              <span className="uppercase tracking-wider">Scheme</span>
              <select
                value={schemeFilter}
                onChange={(e) => setSchemeFilter(e.target.value)}
                className="h-8 cursor-pointer appearance-none rounded-full border border-line bg-surface-2 px-3 text-[11px] text-text outline-none transition-colors duration-500 ease-spring hover:border-line-strong focus:border-accent"
                aria-label="Filter by scheme"
              >
                {schemes.map((s) => (
                  <option key={s} value={s}>
                    {s === 'all' ? 'All' : s}
                  </option>
                ))}
              </select>
            </label>
            <div className="relative flex items-center gap-1 rounded-full border border-line p-0.5">
              {(
                [
                  ['all', 'All'],
                  ['assessed', 'Assessed'],
                  ['unassessed', 'Not assessed'],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setAssessedFilter(key)}
                  className={`relative z-10 rounded-full px-3 py-1 text-[10.5px] transition-colors duration-300 ${
                    assessedFilter === key ? 'text-[#0a0a08]' : 'text-faint hover:text-text'
                  }`}
                  aria-pressed={assessedFilter === key}
                >
                  {assessedFilter === key && (
                    <motion.span
                      layoutId="filter-pill"
                      className="absolute inset-0 rounded-full bg-accent"
                      style={{ zIndex: -1 }}
                      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                    />
                  )}
                  {label}
                </button>
              ))}
            </div>
            <motion.span
              key={`${filteredEndpoints.length}-${filteredParameters.length}`}
              className="mono-cell ml-auto text-[10px] text-faint"
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
            >
              {filteredEndpoints.length} endpoints · {filteredParameters.length} parameters
            </motion.span>
          </motion.div>

          {/* ── Endpoints ── */}
          <motion.section
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-40px' }}
            transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }}
            className="panel overflow-hidden"
          >
            <div className="px-5 pt-5 pb-2">
              <SectionHeader
                title={`Observed endpoints (${filteredEndpoints.length})`}
                icon={<ScanSearch className="h-3.5 w-3.5" aria-hidden="true" />}
                meta="Click a row for provenance and assessment status"
              />
            </div>
            <DataTable
              rows={filteredEndpoints}
              keyField={(e: SurfaceEndpoint) => e.url}
              onRowClick={openEndpoint}
              empty={{
                title: 'No endpoints match',
                description: 'Adjust the scheme or assessment filter, or run discovery to observe more endpoints.',
              }}
              columns={[
                {
                  key: 'url',
                  label: 'Endpoint',
                  render: (e: SurfaceEndpoint) => <UrlValue url={e.url} className="text-[11px]" />,
                },
                {
                  key: 'port',
                  label: 'Port',
                  className: 'whitespace-nowrap',
                  render: (e: SurfaceEndpoint) => (
                    <span className="mono-cell text-[10px] text-muted">{e.port}</span>
                  ),
                },
                {
                  key: 'scheme',
                  label: 'Scheme',
                  render: (e: SurfaceEndpoint) => (
                    <span className="mono-cell text-[10px] text-faint">{e.scheme}</span>
                  ),
                },
                {
                  key: 'assessed',
                  label: 'Assessed',
                  render: (e: SurfaceEndpoint) =>
                    e.assessed ? (
                      <StatusBadge status="completed" label={`${e.assessment_tests} test${e.assessment_tests === 1 ? '' : 's'}`} />
                    ) : (
                      <StatusBadge status="pending" label="Not assessed" />
                    ),
                },
                {
                  key: 'params',
                  label: 'Params',
                  render: (e: SurfaceEndpoint) => (
                    <span className="mono-cell text-[10px] text-muted">{e.parameter_count}</span>
                  ),
                },
                {
                  key: 'sources',
                  label: 'Sources',
                  render: (e: SurfaceEndpoint) => (
                    <div className="flex flex-wrap gap-1">
                      {e.sources.slice(0, 3).map((s) => (
                        <span key={s} className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-faint">
                          {s}
                        </span>
                      ))}
                      {e.sources.length > 3 && (
                        <span className="mono-cell text-[9px] text-faint">+{e.sources.length - 3}</span>
                      )}
                    </div>
                  ),
                },
                {
                  key: 'seen',
                  label: 'Last seen',
                  render: (e: SurfaceEndpoint) => (
                    <span className="mono-cell text-[9.5px] text-faint">{relativeTime(e.last_seen)}</span>
                  ),
                },
              ]}
            />
          </motion.section>

          {/* ── Parameters ── */}
          <motion.section
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-40px' }}
            transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }}
            className="panel overflow-hidden"
          >
            <div className="px-5 pt-5 pb-2">
              <SectionHeader
                title={`Observed parameters (${filteredParameters.length})`}
                icon={<Database className="h-3.5 w-3.5" aria-hidden="true" />}
                meta="Names only — values are never surfaced"
              />
            </div>
            <DataTable
              rows={filteredParameters}
              keyField={(p: SurfaceParameter) => `${p.endpoint}?${p.parameter}`}
              onRowClick={(p) => setSelectedParameter(p)}
              empty={{
                title: 'No parameters match',
                description: 'Parameter names are discovered from persisted observation subjects and explicit candidates.',
              }}
              columns={[
                {
                  key: 'endpoint',
                  label: 'Endpoint',
                  render: (p: SurfaceParameter) => (
                    <span className="minw-0 inline-flex max-w-full items-center gap-1.5">
                      <span className={`dot shrink-0 ${p.assessed ? 'dot-ok' : 'dot-neutral'}`} aria-hidden="true" />
                      <UrlValue url={p.endpoint} maxChars={72} />
                    </span>
                  ),
                },
                {
                  key: 'parameter',
                  label: 'Parameter',
                  render: (p: SurfaceParameter) => (
                    <span className="mono-cell text-[11px] text-accent">{p.parameter}</span>
                  ),
                },
                {
                  key: 'shape',
                  label: 'Value shape',
                  render: (p: SurfaceParameter) => (
                    <span className={`mono-cell text-[10px] ${p.value_shape === 'present' ? 'text-muted' : 'text-faint'}`}>
                      {p.value_shape}
                    </span>
                  ),
                },
                {
                  key: 'sensitive',
                  label: 'Sensitive name',
                  render: (p: SurfaceParameter) =>
                    p.value_sensitive ? (
                      <span className="mono-cell text-[9.5px] text-warn">hint</span>
                    ) : (
                      <span className="text-[9.5px] text-faint">—</span>
                    ),
                },
                {
                  key: 'assessed',
                  label: 'Assessed',
                  render: (p: SurfaceParameter) =>
                    p.assessed ? (
                      <StatusBadge status="completed" label="Assessed" />
                    ) : (
                      <StatusBadge status="pending" label="Not assessed" />
                    ),
                },
                {
                  key: 'sources',
                  label: 'Sources',
                  render: (p: SurfaceParameter) => (
                    <span className="mono-cell text-[9.5px] text-faint">
                      {p.sources.slice(0, 2).join(', ')}
                      {p.sources.length > 2 ? ` +${p.sources.length - 2}` : ''}
                    </span>
                  ),
                },
              ]}
            />
          </motion.section>

          {/* ── Discovery assets ── */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <motion.div
              initial={{ opacity: 0, scale: 0.92 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] }}
            >
              <DiscoveryPanel
                title={`API documents (${surface.api_documents.length})`}
                icon={<FileJson className="h-3.5 w-3.5" aria-hidden="true" />}
                items={surface.api_documents}
                empty="No OpenAPI documents observed — JSON documents may be parsed into endpoints."
              />
            </motion.div>
            <motion.div
              initial={{ opacity: 0, scale: 0.92 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] as [number, number, number, number], delay: 0.08 }}
            >
              <DiscoveryPanel
                title={`Script assets (${surface.script_assets.length})`}
                icon={<FileCode2 className="h-3.5 w-3.5" aria-hidden="true" />}
                items={surface.script_assets}
                empty="No script assets observed."
              />
            </motion.div>
          </div>
        </>
      )}

      {/* Endpoint detail drawer */}
      <DetailDrawer
        open={selectedEndpoint !== null}
        onClose={closeEndpoint}
        title={
          <span className="inline-flex items-center gap-2">
            Endpoint detail
            <span className={`mono-cell rounded-full border px-2 py-0.5 text-[9px] ${activeEndpoint ? borderTone(activeEndpoint) : ''}`}>
              {activeEndpoint?.assessed ? 'assessed' : 'not assessed'}
            </span>
          </span>
        }
        footer={
          activeEndpoint ? (
            <div className="flex w-full items-center justify-between gap-3">
              <CopyButton value={activeEndpoint.url} label="Copy URL" />
              {surface && (
                <Link
                  to={`/surface?scan=${scanId}&endpoint=${encodeURIComponent(activeEndpoint.url)}`}
                  className="rounded-full border border-line bg-surface px-3.5 py-1.5 text-[11px] font-medium text-muted transition-colors hover:border-line-strong hover:text-text"
                >
                  Deep link
                </Link>
              )}
            </div>
          ) : undefined
        }
      >
        {activeEndpoint && (
          <div className="space-y-5">
            <div>
              <p className="eyebrow mb-1.5">URL</p>
              <MonospaceValue value={activeEndpoint.url} copyable className="text-[11.5px] text-text" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Scheme" value={activeEndpoint.scheme} />
              <Field label="Port" value={String(activeEndpoint.port)} note={activeEndpoint.scheme === 'https' ? 'scheme default' : 'explicit or default'} />
              <Field label="Host" value={activeEndpoint.host} />
              <Field label="Parameters" value={String(activeEndpoint.parameter_count)} />
            </div>

            <div>
              <p className="eyebrow mb-2">Provenance</p>
              <div className="flex flex-wrap gap-1.5">
                {activeEndpoint.sources.map((s) => (
                  <span key={s} className="mono-cell rounded-md border border-line px-2 py-1 text-[9.5px] text-muted">{s}</span>
                ))}
              </div>
              <p className="mt-2 text-[10px] leading-relaxed text-faint">
                First seen {relativeTime(activeEndpoint.first_seen)} · Last seen{' '}
                {relativeTime(activeEndpoint.last_seen)}
              </p>
              <p className="mt-1 text-[10px] leading-relaxed text-faint">
                Observation ids:{' '}
                {activeEndpoint.observation_ids.length > 0
                  ? activeEndpoint.observation_ids.map((id) => `#${id}`).join(', ')
                  : '—'}
              </p>
            </div>

            <div className={`rounded-xl border p-3.5 ${activeEndpoint.assessed ? 'border-accent/25 bg-accent/[0.03]' : 'border-line bg-surface-2/60'}`}>
              <p className="eyebrow mb-2">Assessment status</p>
              {activeEndpoint.assessed ? (
                <>
                  <div className="flex flex-wrap gap-1.5">
                    {activeEndpoint.assessment_statuses.map((s) => (
                      <AssessmentBadge key={s} status={s} />
                    ))}
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-faint">
                    {activeEndpoint.assessment_tests} executed/validated/failed test
                    {activeEndpoint.assessment_tests === 1 ? '' : 's'} reference this endpoint. Planned or
                    skipped tests are never counted as assessment evidence.
                  </p>
                </>
              ) : (
                <p className="text-[11px] leading-relaxed text-muted">
                  No executed, validated or failed assessment test references this endpoint yet.
                </p>
              )}
            </div>

            <div>
              <p className="eyebrow mb-2">Observed parameters on this endpoint</p>
              {parametersFor(activeEndpoint.url).length === 0 ? (
                <p className="text-[11px] text-faint">None observed.</p>
              ) : (
                <div className="space-y-1.5">
                  {parametersFor(activeEndpoint.url).map((p) => (
                    <button
                      key={`${p.endpoint}?${p.parameter}`}
                      type="button"
                      onClick={() => setSelectedParameter(p)}
                      className="flex w-full items-center justify-between gap-3 rounded-xl border border-line bg-surface-2/60 px-3 py-2 text-left transition-colors duration-500 ease-spring hover:border-line-strong"
                    >
                      <span className="minw-0 flex items-center gap-2">
                        <span className={`dot shrink-0 ${p.assessed ? 'dot-ok' : 'dot-neutral'}`} aria-hidden="true" />
                        <span className="mono-cell truncate text-[11px] text-accent">{p.parameter}</span>
                      </span>
                      <span className="mono-cell shrink-0 text-[9.5px] text-faint">{p.value_shape}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </DetailDrawer>

      {/* Parameter detail drawer */}
      <DetailDrawer
        open={selectedParameter !== null}
        onClose={() => setSelectedParameter(null)}
        title="Parameter detail"
        footer={
          activeParameter ? (
            <CopyButton value={`${activeParameter.endpoint}?${activeParameter.parameter}`} label="Copy parameter ref" />
          ) : undefined
        }
      >
        {activeParameter && (
          <div className="space-y-5">
            <div>
              <p className="eyebrow mb-1.5">Endpoint</p>
              <UrlValue url={activeParameter.endpoint} className="text-[11.5px]" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Parameter" value={activeParameter.parameter} accent />
              <Field
                label="Value shape"
                value={activeParameter.value_shape}
                note={activeParameter.value_shape === 'present' ? 'values are never surfaced' : 'observed empty'}
              />
              <Field label="Sensitive name" value={activeParameter.value_sensitive ? 'hint' : 'no'} />
              <Field label="Assessed" value={activeParameter.assessed ? 'yes' : 'no'} />
            </div>
            <div className="rounded-xl border border-line bg-surface-2/60 p-3.5">
              <p className="text-[10.5px] leading-relaxed text-muted">
                Assessment status reflects the owning endpoint: only executed/validated/failed tests count.
              </p>
              {activeParameter.assessed && activeParameter.assessment_statuses.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {activeParameter.assessment_statuses.map((s) => (
                    <AssessmentBadge key={s} status={s} />
                  ))}
                </div>
              )}
            </div>
            <div>
              <p className="eyebrow mb-2">Provenance</p>
              <p className="text-[10px] leading-relaxed text-faint">
                Sources: {activeParameter.sources.length > 0 ? activeParameter.sources.join(', ') : '—'}
              </p>
              <p className="mt-1 text-[10px] leading-relaxed text-faint">
                Observation ids:{' '}
                {activeParameter.observation_ids.length > 0
                  ? activeParameter.observation_ids.map((id) => `#${id}`).join(', ')
                  : '—'}
              </p>
              <p className="mt-1 text-[10px] leading-relaxed text-faint">
                First seen {relativeTime(activeParameter.first_seen)} · Last seen{' '}
                {relativeTime(activeParameter.last_seen)}
              </p>
              {activeParameter.first_seen && (
                <p className="mt-1 text-[10px] leading-relaxed text-faint">
                  Exact observed {formatDateTime(activeParameter.first_seen)}
                </p>
              )}
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════════════════════════
   Sub-components — upgraded with animations
   ═══════════════════════════════════════════════════════════════════════════ */

const AssessmentBadge: React.FC<{ status: string }> = ({ status }) => {
  const s = (status || '').toLowerCase();
  if (s === 'executed' || s === 'validated') {
    return <StatusBadge status="completed" label={s} />;
  }
  if (s === 'failed') {
    return <StatusBadge status="failed" label={s} />;
  }
  return <StatusBadge status={s} />;
};

/* ── Animated stat tile ── */
const AnimatedTile: React.FC<{
  label: string;
  value: number;
  accent?: boolean;
  icon: React.ReactNode;
  index: number;
}> = ({ label, value, accent, icon, index }) => {
  const { display, ref } = useAnimatedCounter(value);
  return (
    <motion.div
      variants={fadeUp}
      className="panel group relative overflow-hidden p-5 transition-shadow duration-500 hover:shadow-glow"
      whileHover={{ y: -2, transition: { duration: 0.25 } }}
    >
      {/* Accent glow on hover */}
      <div className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-accent/[0.06] via-transparent to-transparent opacity-0 transition-opacity duration-500 group-hover:opacity-100" />

      <div className="mb-2 flex items-center gap-1.5">
        <span className={`${accent ? 'text-accent' : 'text-faint'} transition-colors duration-300 group-hover:text-accent`}>
          {icon}
        </span>
        <p className="eyebrow">{label}</p>
      </div>
      <p
        ref={ref}
        className={`tnum text-[28px] font-semibold leading-none tracking-tight ${accent ? 'text-accent' : 'text-text'}`}
      >
        {display}
      </p>

      {/* Subtle activity indicator line */}
      <motion.div
        className={`absolute bottom-0 left-0 h-[2px] ${accent ? 'bg-accent' : 'bg-line-strong'}`}
        initial={{ width: '0%' }}
        whileInView={{ width: '100%' }}
        viewport={{ once: true }}
        transition={{ duration: 0.8, delay: index * 0.08, ease: [0.22, 1, 0.36, 1] }}
      />
    </motion.div>
  );
};

/* ── Animated coverage bar with glow ── */
const AnimatedCoverageBar: React.FC<{
  done: number;
  total: number;
  tone: 'accent' | 'high';
}> = ({ done, total, tone }) => {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  const barRef = useRef<HTMLDivElement>(null);
  const isInView = useInView(barRef, { once: true, margin: '-20px' });

  const toneColors = {
    accent: {
      bar: 'bg-accent',
      glow: 'rgba(232, 255, 61, 0.35)',
      text: 'text-accent',
    },
    high: {
      bar: 'bg-high',
      glow: 'rgba(255, 143, 77, 0.35)',
      text: 'text-high',
    },
  };

  const c = toneColors[tone];

  return (
    <div ref={barRef}>
      <div className="mb-1.5 flex items-center justify-between gap-3">
        <span className="text-[10px] text-faint">Coverage</span>
        <span className={`mono-cell text-[10px] ${c.text}`}>
          {done}/{total} · {pct}%
        </span>
      </div>
      <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-surface-2">
        <motion.div
          className={`h-full rounded-full ${c.bar}`}
          initial={{ width: '0%' }}
          animate={isInView ? { width: `${pct}%` } : { width: '0%' }}
          transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1], delay: 0.2 }}
          style={{
            boxShadow: isInView ? `0 0 12px ${c.glow}, 0 0 4px ${c.glow}` : 'none',
          }}
        />
        {/* Shimmer sweep on the bar */}
        {isInView && pct > 0 && (
          <motion.div
            className="absolute inset-y-0 w-12 rounded-full"
            style={{
              background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent)',
            }}
            initial={{ left: '-3rem' }}
            animate={{ left: '100%' }}
            transition={{ duration: 1.6, delay: 0.8, ease: 'linear' }}
          />
        )}
      </div>
    </div>
  );
};

/* ── Host card with hover lift ── */
const HostCard: React.FC<{
  host: { host: string; ports: number[]; schemes: string[]; kinds: string[]; first_seen: string | null; last_seen: string | null };
  index: number;
}> = ({ host: h, index }) => (
  <motion.div
    variants={fadeUp}
    className="group rounded-xl border border-line bg-surface-2/60 px-3 py-2.5 transition-all duration-500 hover:border-accent/20 hover:bg-accent/[0.02] hover:shadow-[0_0_20px_-8px_rgba(232,255,61,0.12)]"
    whileHover={{ y: -1, transition: { duration: 0.2 } }}
  >
    <div className="flex items-center justify-between gap-2">
      <span className="mono-cell truncate text-[11.5px] text-text transition-colors duration-300 group-hover:text-accent">{h.host}</span>
      <span className="mono-cell flex shrink-0 gap-1 text-[9.5px] text-faint">
        {h.ports.length > 0 ? h.ports.join('/') : '—'}
      </span>
    </div>
    <div className="mt-1.5 flex flex-wrap items-center gap-1">
      {h.schemes.map((scheme) => (
        <span key={scheme} className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-muted transition-colors duration-300 group-hover:border-accent/20">
          {scheme}
        </span>
      ))}
      {h.kinds.slice(0, 4).map((kind) => (
        <span key={kind} className="mono-cell rounded-md border border-accent/30 bg-accent/5 px-1.5 py-0.5 text-[9px] text-accent">
          {kind}
        </span>
      ))}
      {h.kinds.length > 4 && (
        <span className="mono-cell text-[9px] text-faint">+{h.kinds.length - 4}</span>
      )}
    </div>
    <p className="mt-1.5 mono-cell text-[8.5px] text-faint">
      first {relativeTime(h.first_seen)} · last {relativeTime(h.last_seen)}
    </p>
  </motion.div>
);

const Field: React.FC<{ label: string; value: string; note?: string; accent?: boolean }> = ({
  label,
  value,
  note,
  accent,
}) => (
  <div className="rounded-xl border border-line bg-surface-2/60 px-3 py-2.5">
    <p className="eyebrow mb-1">{label}</p>
    <p className={`mono-cell text-[12px] ${accent ? 'text-accent' : 'text-text'}`}>{value}</p>
    {note && <p className="mt-0.5 text-[9px] text-faint">{note}</p>}
  </div>
);

const DiscoveryPanel: React.FC<{
  title: string;
  icon: React.ReactNode;
  items: {
    id: number;
    url: string;
    kind: string;
    data: Record<string, unknown>;
    source?: string | null;
    observed_at: string | null;
  }[];
  empty: string;
}> = ({ title, icon, items, empty }) => (
  <section className="panel group relative overflow-hidden">
    <div className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-accent/[0.03] via-transparent to-transparent opacity-0 transition-opacity duration-700 group-hover:opacity-100" />
    <div className="flex items-center gap-2 px-5 pt-5 pb-3">
      <span className="text-accent">{icon}</span>
      <h2 className="text-[12.5px] font-semibold text-text">{title}</h2>
    </div>
    <div className="scrollbar-thin max-h-72 space-y-1.5 overflow-y-auto px-5 pb-5">
      {items.length === 0 ? (
        <p className="text-[11px] text-faint">{empty}</p>
      ) : (
        items.map((a) => (
          <div key={a.id} className="rounded-xl border border-line bg-surface-2/60 px-3 py-2.5 transition-colors duration-300 hover:border-accent/15">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono-cell min-w-0 flex-1 truncate text-[10.5px] text-text">{a.url}</span>
              <span className="mono-cell shrink-0 text-[9px] text-faint">#{a.id}</span>
            </div>
            <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[9.5px] text-faint">
              <span>kind: {a.kind}</span>
              {a.source && <span>source: {a.source}</span>}
              <span>{relativeTime(a.observed_at)}</span>
            </p>
          </div>
        ))
      )}
    </div>
  </section>
);

export default AttackSurface;