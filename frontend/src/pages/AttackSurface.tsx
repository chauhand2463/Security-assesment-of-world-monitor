import React, { useState, useEffect, useCallback } from 'react';
import {
  Radar,
  FileJson,
  FileCode2,
  Fingerprint,
  Globe,
  ShieldCheck,
  Lock,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  getScanSurface,
} from '../api';
import type { SurfaceSnapshot, SurfaceEndpoint, SurfaceParameter } from '../api';
import { PageHeader } from '../components/PageHeader';
import { ScanPicker } from '../components/ScanPicker';
import { DataTable } from '../components/DataTable';
import { EmptyState } from '../components/EmptyState';
import { SkeletonTable, SkeletonPanel } from '../components/Skeleton';
import { relativeTime } from '../components/format';

export const AttackSurface: React.FC = () => {
  const [scanId, setScanId] = useState<number | null>(null);
  const [surface, setSurface] = useState<SurfaceSnapshot | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchSurface = useCallback(async (id: number) => {
    setLoading(true);
    setSurface(null);
    try {
      setSurface(await getScanSurface(id));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (scanId === null) return;
    fetchSurface(scanId);
  }, [scanId, fetchSurface]);

  const ctx = surface?.context;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Inventory / Attack Surface"
        title="Attack surface"
        description="Observed endpoints, parameters, hosts and discovery assets for one assessment. Every row traces back to a persisted observation — nothing is inferred, and parameter values are never surfaced."
        actions={
          <ScanPicker value={scanId} onChange={setScanId} />
        }
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
      ) : !surface ? (
        <EmptyState
          icon={<Radar className="h-4 w-4" aria-hidden="true" />}
          title="No surface recorded"
          description="This assessment has no persisted observations yet, so no surface can be shown."
        />
      ) : (
        <>
          {/* Redaction notice */}
          <div className="flex items-start gap-2.5 rounded-2xl border border-line bg-surface-2/60 p-3.5">
            <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" strokeWidth={1.5} aria-hidden="true" />
            <p className="text-[11px] leading-relaxed text-muted">
              Observation-based only. Methods are never inferred from URLs and parameter values / credential material are
              never surfaced — you see names, existence shapes, and provenance.
            </p>
          </div>

          {/* Stat tiles */}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            <Tile label="Endpoints observed" value={surface.endpoint_count} />
            <Tile label="Parameters observed" value={surface.parameter_count} accent />
            <Tile label="Hosts observed" value={ctx?.host_count ?? 0} />
            <Tile label="API documents" value={surface.api_documents.length} />
            <Tile label="Script assets" value={surface.script_assets.length} />
          </div>

          {/* Surface coverage gauge */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section className="panel p-5">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                  <ShieldCheck className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                  Endpoint coverage
                </h2>
                <span className="mono-cell text-[10px] text-faint">
                  {surface.coverage.endpoints_assessed}/{surface.coverage.endpoints_total} assessed
                </span>
              </div>
              <Bar
                value={surface.coverage.endpoints_total}
                done={surface.coverage.endpoints_assessed}
                tone="bg-accent"
              />
              <p className="mt-2.5 text-[10px] leading-relaxed text-faint">{surface.coverage.note}</p>
            </section>
            <section className="panel p-5">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                  <Fingerprint className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                  Parameter coverage
                </h2>
                <span className="mono-cell text-[10px] text-faint">
                  {surface.coverage.parameters_assessed}/{surface.coverage.parameters_total} assessed
                </span>
              </div>
              <Bar
                value={surface.coverage.parameters_total}
                done={surface.coverage.parameters_assessed}
                tone="bg-high"
              />
              <p className="mt-2.5 text-[10px] leading-relaxed text-faint">
                Assessed where the owning endpoint has executed/validated/failed assessment tests.
              </p>
            </section>
          </div>

          {/* Context */}
          <section className="panel overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-3">
              <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                <Globe className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                Observed context
              </h2>
              <span className="mono-cell text-[10px] text-faint">
                {ctx?.http_subjects ?? 0} HTTP subjects · {ctx?.observation_count ?? 0} observations · {ctx?.sources?.length ?? 0} sources
              </span>
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

          {/* Endpoints */}
          <section className="panel overflow-hidden">
            <div className="px-5 pt-5 pb-2">
              <h2 className="text-[12.5px] font-semibold text-text">Observed endpoints ({surface.endpoints.length})</h2>
            </div>
            <DataTable
              rows={surface.endpoints}
              keyField={(e: SurfaceEndpoint) => e.url}
              empty={{
                title: 'No endpoints observed',
                description: 'Endpoints appear from real persisted HTTP(S) observation subjects.',
              }}
              columns={[
                {
                  key: 'url',
                  label: 'Endpoint',
                  render: (e: SurfaceEndpoint) => <span className="mono-cell text-[11px] text-text break-all">{e.url}</span>,
                },
                {
                  key: 'scheme',
                  label: 'Scheme',
                  render: (e: SurfaceEndpoint) => <span className="mono-cell text-[10px] text-faint">{e.scheme}</span>,
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
              <h2 className="text-[12.5px] font-semibold text-text">Observed parameters ({surface.parameters.length})</h2>
              <p className="mt-1 text-[10px] text-faint">Names only — values are never surfaced.</p>
            </div>
            <DataTable
              rows={surface.parameters}
              keyField={(p: SurfaceParameter) => `${p.endpoint}?${p.parameter}`}
              empty={{
                title: 'No parameters observed',
                description: 'Parameter names are discovered from persisted observation subjects and explicit candidates.',
              }}
              columns={[
                {
                  key: 'endpoint',
                  label: 'Endpoint',
                  render: (p: SurfaceParameter) => <span className="mono-cell text-[10.5px] text-text truncate">{p.endpoint}</span>,
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
    </div>
  );
};

const Tile: React.FC<{ label: string; value: number; accent?: boolean }> = ({ label, value, accent }) => (
  <div className="panel p-5">
    <p className="eyebrow mb-1.5">{label}</p>
    <p className={`tnum text-[26px] font-semibold leading-none tracking-tight ${accent ? 'text-accent' : 'text-text'}`}>
      {value}
    </p>
  </div>
);

const Bar: React.FC<{ value: number; done: number; tone: string }> = ({ value, done, tone }) => {
  const pct = value > 0 ? Math.min(100, Math.round((done / value) * 100)) : 0;
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-surface-2">
      <div className={`h-full rounded-full ${tone} transition-[width] duration-700 ease-spring`} style={{ width: `${pct}%` }} />
    </div>
  );
};

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
    <div className="max-h-72 space-y-1.5 overflow-y-auto px-5 pb-5">
      {items.length === 0 ? (
        <p className="text-[11px] text-faint">{empty}</p>
      ) : (
        items.map((a) => (
          <div key={a.id} className="rounded-xl border border-line bg-surface-2/60 px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono-cell truncate text-[10.5px] text-text">{a.url}</span>
              <span className="mono-cell ml-auto shrink-0 text-[9px] text-faint">#{a.id}</span>
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