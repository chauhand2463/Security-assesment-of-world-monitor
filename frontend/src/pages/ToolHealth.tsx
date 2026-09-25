import React, { useState, useEffect, useCallback } from 'react';
import { Cpu, CheckCircle2, Ban, Activity, RotateCw, History } from 'lucide-react';
import { apiFetch, getToolsExecutions } from '../api';
import type { ToolExecutionLedger, ToolExecutionSummary } from '../api';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { Skeleton } from '../components/Skeleton';
import { DataTable } from '../components/DataTable';
import { relativeTime } from '../components/format';

const CATEGORY_LABELS: Record<string, string> = {
  recon: 'Recon',
  dns: 'DNS',
  service: 'Service',
  http: 'HTTP',
  vulnerability: 'Vulnerability',
  probe: 'Stdlib probe',
};

export const ToolHealth: React.FC = () => {
  const [data, setData] = useState<{ tools: any[]; simulation_mode: boolean } | null>(null);
  const [ledger, setLedger] = useState<ToolExecutionLedger | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadExecutions = useCallback(async () => {
    const rows = await getToolsExecutions();
    setLedger(rows);
  }, []);

  const fetchInventory = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [res, exec] = await Promise.all([apiFetch('/tools/inventory'), loadExecutions()]);
      if (res.ok) {
        setData(await res.json());
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load tool inventory.');
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, [loadExecutions]);

  const reprobe = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      // Re-merge freshly installed PATH entries before re-probing so a tool
      // installed after the backend started becomes visible without recovery.
      await apiFetch('/tools/refresh', { method: 'POST' });
      const [res, exec] = await Promise.all([apiFetch('/tools/inventory'), loadExecutions()]);
      if (res.ok) {
        setData(await res.json());
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load tool inventory.');
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, [loadExecutions]);

  useEffect(() => {
    fetchInventory();
  }, [fetchInventory]);

  const tools = data?.tools ?? [];
  const installed = tools.filter((t) => t.installed).length;
  const missing = tools.filter((t) => !t.installed).length;
  const categories = [...new Set(tools.map((t) => t.category))];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Intelligence / Tool Health"
        title="Tool health"
        description="Live scanner availability. Detection is honest — via real shutil.which probes on the host. Re-probe re-reads your PATH (and TOOL_PATH) so binaries installed after launch appear without a restart."
        actions={
          <button
            onClick={reprobe}
            className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
          >
            <RotateCw className="w-3 h-3" aria-hidden="true" />
            Re-probe
          </button>
        }
      />

      {error ? (
        <ErrorState message={error} onRetry={fetchInventory} />
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <Tile
              label="Registered tools"
              icon={<Cpu className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />}
              value={tools.length}
              loading={loading}
            />
            <Tile
              label="Installed / callable"
              icon={<CheckCircle2 className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />}
              value={installed}
              loading={loading}
            />
            <Tile
              label="Missing / not installed"
              icon={<Ban className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />}
              value={missing}
              loading={loading}
            />
          </div>

          {ledger && (
            <section className="panel overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5 pb-3">
                <h2 className="flex items-center gap-2 text-[12.5px] font-semibold text-text">
                  <History className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                  Execution summary
                </h2>
                <span className="mono-cell text-[10px] text-faint">
                  {ledger.totals.executions} execution rows · across all assessments
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-1.5 px-5 pb-4">
                <LedgerChip label="completed" value={ledger.totals.completed} tone="text-accent border-accent/30 bg-accent/[0.05]" />
                <LedgerChip label="failed" value={ledger.totals.failed} tone="text-critical border-critical/30 bg-critical/[0.05]" />
                <LedgerChip label="timeout" value={ledger.totals.timeout} tone="text-medium border-medium/30 bg-medium/[0.05]" />
                <LedgerChip label="not installed" value={ledger.totals.not_installed} tone="text-warn border-medium/30 bg-medium/[0.05]" />
                <LedgerChip label="parse failed" value={ledger.totals.parse_failed} tone="text-warn border-medium/30 bg-medium/[0.05]" />
                <LedgerChip label="skipped" value={ledger.totals.skipped} tone="text-faint border-line" />
                <LedgerChip label="cancelled" value={ledger.totals.cancelled} tone="text-faint border-line" />
                <LedgerChip label="observations produced" value={ledger.totals.observations_produced} tone="text-accent border-accent/30 bg-accent/[0.05]" />
              </div>
              <DataTable
                rows={ledger.tools}
                keyField={(t: ToolExecutionSummary) => t.tool}
                empty={{
                  title: 'No tool executions yet',
                  description: 'Tool execution rows appear once assessments have run and persisted their tool runs.',
                }}
                columns={[
                  {
                    key: 'tool',
                    label: 'Tool',
                    render: (t: ToolExecutionSummary) => (
                      <span className="mono-cell text-[11px] font-medium text-text">{t.tool}</span>
                    ),
                  },
                  {
                    key: 'category',
                    label: 'Category',
                    render: (t: ToolExecutionSummary) => (
                      <span className="mono-cell text-[9.5px] text-faint">{t.category}</span>
                    ),
                  },
                  {
                    key: 'executions',
                    label: 'Runs',
                    render: (t: ToolExecutionSummary) => (
                      <span className="mono-cell text-[10.5px] text-muted">{t.executions_total}</span>
                    ),
                  },
                  {
                    key: 'statuses',
                    label: 'Outcomes',
                    render: (t: ToolExecutionSummary) => (
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(t.statuses ?? {}).map(([s, n]) => (
                          <span
                            key={s}
                            className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-faint"
                            title={`${s}: ${n}`}
                          >
                            {s === 'completed'
                              ? '✓'
                              : s === 'failed'
                              ? '✕'
                              : s === 'cancelled'
                              ? '⊘'
                              : '•'}{' '}
                            {n}
                          </span>
                        ))}
                      </div>
                    ),
                  },
                  {
                    key: 'obs',
                    label: 'Obs produced',
                    render: (t: ToolExecutionSummary) => (
                      <span className="mono-cell text-[10px] text-muted">{t.observations_produced}</span>
                    ),
                  },
                  {
                    key: 'last_status',
                    label: 'Last run',
                    render: (t: ToolExecutionSummary) => (
                      <div className="flex flex-wrap items-center gap-1.5">
                        {t.last_status ? <StatusBadge status={t.last_status} /> : <span className="text-[9.5px] text-faint">—</span>}
                        <span className="mono-cell text-[9px] text-faint">{relativeTime(t.last_execution_at)}</span>
                      </div>
                    ),
                  },
                  {
                    key: 'scans',
                    label: 'Scans',
                    render: (t: ToolExecutionSummary) => (
                      <span className="mono-cell text-[10px] text-faint">{t.scans_touched}</span>
                    ),
                  },
                ]}
              />
              <p className="px-5 pt-3 pb-5 text-[10px] leading-relaxed text-faint">
                Outcomes and produced-observation counts come from persisted `ToolExecution` rows — mirrored from the
                Coverage page. Status totals are exact ledger counts, not estimates.
              </p>
            </section>
          )}

          {data && (
            <div className="panel flex flex-wrap items-center gap-2.5 p-4 text-[11.5px] text-muted">
              <Activity className="w-3.5 h-3.5 text-accent" aria-hidden="true" />
              <span>
                Execution mode: <StatusBadge status={data.simulation_mode ? 'Running' : 'Completed'} label={data.simulation_mode ? 'Simulation' : 'Live'} />
              </span>
              <span className="text-faint">
                {data.simulation_mode
                  ? '— adapters emit simulated outcomes.'
                  : '— missing binaries are reported as NOT INSTALLED and never faked.'}
              </span>
            </div>
          )}

          {!loading && data && tools.length > 0 && installed === 0 && (
            <div className="panel border-warn/30 bg-warn/[0.05] p-4 text-[11.5px] leading-relaxed text-muted">
              <p className="font-medium text-text">No scanner binaries found on PATH</p>
              <p className="mt-1">
                Install the scanners you want (a package manager or <code className="font-mono">go install</code>), then
                click <span className="text-text">Re-probe</span>. If a binary lives outside PATH, add its folder to the{' '}
                <code className="font-mono">TOOL_PATH</code> variable in{' '}
                <code className="font-mono">backend/.env</code> and restart the backend.
              </p>
            </div>
          )}

          {loading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-20 w-full rounded-2xl" />
              ))}
            </div>
          ) : tools.length === 0 ? (
            <EmptyState title="No tools registered" description="The inventory endpoint reported no scanners." />
          ) : (
            <div className="space-y-5">
              {categories.map((cat) => (
                <div key={cat}>
                  <h2 className="mb-2.5 text-[12.5px] font-semibold text-text">
                    {CATEGORY_LABELS[cat] || cat}
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {tools
                      .filter((t) => t.category === cat)
                      .map((tool) => (
                        <div key={tool.tool} className="panel flex items-start justify-between gap-3 p-4">
                          <div className="min-w-0 space-y-1">
                            <div className="flex items-center gap-2">
                              <StatusBadge status={tool.installed ? 'Completed' : 'Failed'} label="" />
                              <span className="mono-cell text-[11.5px] font-semibold text-text">{tool.tool}</span>
                            </div>
                            <div className="text-[10.5px] text-faint space-y-0.5">
                              {tool.binary && (
                                <p className="truncate">binary: <code className="font-mono text-muted">{tool.binary}</code></p>
                              )}
                              {tool.version && (
                                <p>version: <code className="font-mono text-accent">{tool.version}</code></p>
                              )}
                              {tool.path && <p className="truncate" title={tool.path}>path: <code className="font-mono text-muted">{tool.path}</code></p>}
                              {(tool.note || (!tool.installed && !tool.binary)) && (
                                <p className="text-medium/80">{tool.note || 'stdlib probe — no external binary required'}</p>
                              )}
                            </div>
                          </div>
                          <span
                            className={`shrink-0 mono-cell text-[9px] px-2 py-0.5 rounded-full border ${
                              tool.installed
                                ? 'text-accent border-accent/40 bg-accent/10'
                                : 'text-medium border-medium/40 bg-medium/10'
                            }`}
                          >
                            {tool.installed ? 'INSTALLED' : 'NOT INSTALLED'}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

const Tile: React.FC<{ label: string; icon: React.ReactNode; value: number; loading?: boolean }> = ({ label, icon, value, loading }) => (
  <div className="panel flex items-center gap-3.5 p-5">
    <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-line bg-surface-2 text-accent">
      {icon}
    </span>
    <div>
      <p className="eyebrow mb-1.5">{label}</p>
      {loading ? (
        <Skeleton className="h-6 w-10" />
      ) : (
        <span className="tnum text-[26px] font-semibold leading-none tracking-tight text-text">{value}</span>
      )}
    </div>
  </div>
);

const LedgerChip: React.FC<{ label: string; value: number; tone: string }> = ({ label, value, tone }) => (
  <span className={`mono-cell rounded-md border px-2 py-1 text-[9.5px] ${tone}`}>
    {label}: {value}
  </span>
);