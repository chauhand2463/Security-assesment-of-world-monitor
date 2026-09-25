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
} from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
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
        <div className="space-y-4">
          <SkeletonTable rows={3} cols={4} />
          <SkeletonPanel className="min-h-[220px]" />
        </div>
      ) : error && !surface ? (
        <div className="rounded-2xl border border-critical/25 bg-critical/[0.05] px-5 py-8 text-center text-[12px] text-critical">
          {error}
        </div>
      ) : !surface ? (
        <EmptyState
          icon={<Radar className="h-4 w-4" aria-hidden="true" />}
          title="No surface recorded"
          description="This assessment has no persisted observations yet, so no surface can be shown."
        />
      ) : (
        <>
          <div className="flex items-start gap-2.5 rounded-2xl border border-line bg-surface-2/60 p-3.5">
            <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" strokeWidth={1.5} aria-hidden="true" />
            <p className="text-[11px] leading-relaxed text-muted">
              Observation-based only. Methods are never inferred from URLs and parameter values / credential
              material are never surfaced — you see names, existence shapes, and provenance.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            <Tile label="Endpoints observed" value={surface.endpoint_count} />
            <Tile label="Endpoints assessed" value={surface.coverage.endpoints_assessed} accent />
            <Tile label="Parameters observed" value={surface.parameter_count} />
            <Tile label="Hosts observed" value={ctx?.host_count ?? 0} />
            <Tile label="Discovery assets" value={surface.api_documents.length + surface.script_assets.length} />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section className="panel p-5">
              <SectionHeader
                title="Endpoint coverage"
                icon={<ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />}
                meta={`${surface.coverage.endpoints_assessed}/${surface.coverage.endpoints_total} assessed`}
              />
              <div className="mt-3">
                <CoverageBar
                  done={surface.coverage.endpoints_assessed}
                  total={surface.coverage.endpoints_total}
                  tone="bg-accent"
                />
              </div>
              <p className="mt-2.5 text-[10px] leading-relaxed text-faint">{surface.coverage.note}</p>
            </section>
            <section className="panel p-5">
              <SectionHeader
                title="Parameter coverage"
                icon={<Fingerprint className="h-3.5 w-3.5" aria-hidden="true" />}
                meta={`${surface.coverage.parameters_assessed}/${surface.coverage.parameters_total} assessed`}
              />
              <div className="mt-3">
                <CoverageBar
                  done={surface.coverage.parameters_assessed}
                  total={surface.coverage.parameters_total}
                  tone="bg-high"
                />
              </div>
              <p className="mt-2.5 text-[10px] leading-relaxed text-faint">
                Assessed where the owning endpoint has executed/validated/failed assessment tests.
              </p>
            </section>
          </div>

          {/* Context */}
          <section className="panel overflow-hidden">
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
                  {ctx.hosts.slice(0, 24).map((h) => (
                    <div key={h.host} className="rounded-xl border border-line bg-surface-2/60 px-3 py-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="mono-cell truncate text-[11.5px] text-text">{h.host}</span>
                        <span className="mono-cell flex shrink-0 gap-1 text-[9.5px] text-faint">
                          {h.ports.length > 0 ? h.ports.join('/') : '—'}
                        </span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap items-center gap-1">
                        {h.schemes.map((scheme) => (
                          <span key={scheme} className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-muted">
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
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>

          {/* Filter toolbar */}
          <div className="flex flex-wrap items-center gap-2.5">
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
            <div className="flex items-center gap-1 rounded-full border border-line p-0.5">
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
                  className={`rounded-full px-3 py-1 text-[10.5px] transition-colors duration-500 ease-spring ${
                    assessedFilter === key ? 'bg-accent text-[#0a0a08]' : 'text-faint hover:text-text'
                  }`}
                  aria-pressed={assessedFilter === key}
                >
                  {label}
                </button>
              ))}
            </div>
            <span className="mono-cell ml-auto text-[10px] text-faint">
              {filteredEndpoints.length} endpoints · {filteredParameters.length} parameters
            </span>
          </div>

          {/* Endpoints */}
          <section className="panel overflow-hidden">
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
          </section>

          {/* Parameters */}
          <section className="panel overflow-hidden">
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
          </section>

          {/* Discovery assets */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <DiscoveryPanel
              title={`API documents (${surface.api_documents.length})`}
              icon={<FileJson className="h-3.5 w-3.5" aria-hidden="true" />}
              items={surface.api_documents}
              empty="No OpenAPI documents observed — JSON documents may be parsed into endpoints."
            />
            <DiscoveryPanel
              title={`Script assets (${surface.script_assets.length})`}
              icon={<FileCode2 className="h-3.5 w-3.5" aria-hidden="true" />}
              items={surface.script_assets}
              empty="No script assets observed."
            />
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
            <span className={`mono-cell rounded-full border px-2 py-0.5 text-[9px] ${selectedEndpoint ? borderTone(selectedEndpoint) : ''}`}>
              {selectedEndpoint?.assessed ? 'assessed' : 'not assessed'}
            </span>
          </span>
        }
        footer={
          <>
            <CopyButton value={selectedEndpoint?.url ?? ''} label="Copy URL" />
            {selectedEndpoint && surface && (
              <Link
                to={`/surface?scan=${scanId}&endpoint=${encodeURIComponent(selectedEndpoint.url)}`}
                className="rounded-full border border-line px-3.5 py-1.5 text-[11px] text-muted transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text"
              >
                Deep link
              </Link>
            )}
          </>
        }
      >
        {selectedEndpoint && (
          <div className="space-y-5">
            <div>
              <p className="eyebrow mb-1.5">URL</p>
              <MonospaceValue value={selectedEndpoint.url} copyable className="text-[11.5px] text-text" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Scheme" value={selectedEndpoint.scheme} />
              <Field label="Port" value={String(selectedEndpoint.port)} note={selectedEndpoint.scheme === 'https' ? 'scheme default' : 'explicit or default'} />
              <Field label="Host" value={selectedEndpoint.host} />
              <Field label="Parameters" value={String(selectedEndpoint.parameter_count)} />
            </div>

            <div>
              <p className="eyebrow mb-2">Provenance</p>
              <div className="flex flex-wrap gap-1.5">
                {selectedEndpoint.sources.map((s) => (
                  <span key={s} className="mono-cell rounded-md border border-line px-2 py-1 text-[9.5px] text-muted">{s}</span>
                ))}
              </div>
              <p className="mt-2 text-[10px] leading-relaxed text-faint">
                First seen {relativeTime(selectedEndpoint.first_seen)} · Last seen{' '}
                {relativeTime(selectedEndpoint.last_seen)}
              </p>
              <p className="mt-1 text-[10px] leading-relaxed text-faint">
                Observation ids:{' '}
                {selectedEndpoint.observation_ids.length > 0
                  ? selectedEndpoint.observation_ids.map((id) => `#${id}`).join(', ')
                  : '—'}
              </p>
            </div>

            <div className={`rounded-xl border p-3.5 ${selectedEndpoint.assessed ? 'border-accent/25 bg-accent/[0.03]' : 'border-line bg-surface-2/60'}`}>
              <p className="eyebrow mb-2">Assessment status</p>
              {selectedEndpoint.assessed ? (
                <>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedEndpoint.assessment_statuses.map((s) => (
                      <AssessmentBadge key={s} status={s} />
                    ))}
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-faint">
                    {selectedEndpoint.assessment_tests} executed/validated/failed test
                    {selectedEndpoint.assessment_tests === 1 ? '' : 's'} reference this endpoint. Planned or
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
              {parametersFor(selectedEndpoint.url).length === 0 ? (
                <p className="text-[11px] text-faint">None observed.</p>
              ) : (
                <div className="space-y-1.5">
                  {parametersFor(selectedEndpoint.url).map((p) => (
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
          selectedParameter ? (
            <CopyButton value={`${selectedParameter.endpoint}?${selectedParameter.parameter}`} label="Copy parameter ref" />
          ) : undefined
        }
      >
        {selectedParameter && (
          <div className="space-y-5">
            <div>
              <p className="eyebrow mb-1.5">Endpoint</p>
              <UrlValue url={selectedParameter.endpoint} className="text-[11.5px]" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Parameter" value={selectedParameter.parameter} accent />
              <Field
                label="Value shape"
                value={selectedParameter.value_shape}
                note={selectedParameter.value_shape === 'present' ? 'values are never surfaced' : 'observed empty'}
              />
              <Field label="Sensitive name" value={selectedParameter.value_sensitive ? 'hint' : 'no'} />
              <Field label="Assessed" value={selectedParameter.assessed ? 'yes' : 'no'} />
            </div>
            <div className="rounded-xl border border-line bg-surface-2/60 p-3.5">
              <p className="text-[10.5px] leading-relaxed text-muted">
                Assessment status reflects the owning endpoint: only executed/validated/failed tests count.
              </p>
              {selectedParameter.assessed && selectedParameter.assessment_statuses.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {selectedParameter.assessment_statuses.map((s) => (
                    <AssessmentBadge key={s} status={s} />
                  ))}
                </div>
              )}
            </div>
            <div>
              <p className="eyebrow mb-2">Provenance</p>
              <p className="text-[10px] leading-relaxed text-faint">
                Sources: {selectedParameter.sources.length > 0 ? selectedParameter.sources.join(', ') : '—'}
              </p>
              <p className="mt-1 text-[10px] leading-relaxed text-faint">
                Observation ids:{' '}
                {selectedParameter.observation_ids.length > 0
                  ? selectedParameter.observation_ids.map((id) => `#${id}`).join(', ')
                  : '—'}
              </p>
              <p className="mt-1 text-[10px] leading-relaxed text-faint">
                First seen {relativeTime(selectedParameter.first_seen)} · Last seen{' '}
                {relativeTime(selectedParameter.last_seen)}
              </p>
              {selectedParameter.first_seen && (
                <p className="mt-1 text-[10px] leading-relaxed text-faint">
                  Exact observed {formatDateTime(selectedParameter.first_seen)}
                </p>
              )}
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
};

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

const Tile: React.FC<{ label: string; value: number; accent?: boolean }> = ({ label, value, accent }) => (
  <div className="panel p-5">
    <p className="eyebrow mb-1.5">{label}</p>
    <p className={`tnum text-[26px] font-semibold leading-none tracking-tight ${accent ? 'text-accent' : 'text-text'}`}>
      {value}
    </p>
  </div>
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
  <section className="panel overflow-hidden">
    <div className="flex items-center gap-2 px-5 pt-5 pb-3">
      <span className="text-accent">{icon}</span>
      <h2 className="text-[12.5px] font-semibold text-text">{title}</h2>
    </div>
    <div className="scrollbar-thin max-h-72 space-y-1.5 overflow-y-auto px-5 pb-5">
      {items.length === 0 ? (
        <p className="text-[11px] text-faint">{empty}</p>
      ) : (
        items.map((a) => (
          <div key={a.id} className="rounded-xl border border-line bg-surface-2/60 px-3 py-2.5">
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