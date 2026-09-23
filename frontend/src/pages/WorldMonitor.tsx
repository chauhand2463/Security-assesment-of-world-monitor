import React, { useEffect, useState } from 'react';
import {
  Globe,
  Plus,
  RefreshCw,
  ScanSearch,
  Trash2,
  CheckCircle2,
  XCircle,
  Loader2,
  ShieldAlert,
  Blocks,
} from 'lucide-react';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { Button } from '../components/Button';
import { Input } from '../components/Field';
import { EmptyState } from '../components/EmptyState';
import { formatDateTime } from '../components/format';

const WM_TONES: Record<string, string> = {
  not_configured: 'text-faint border-line',
  checking: 'text-warn border-warn/40 bg-warn/5',
  reachable: 'text-accent border-accent/40 bg-accent/5',
  unavailable: 'text-critical border-critical/40 bg-critical/5',
  discovered: 'text-accent border-accent/40 bg-accent/5',
  partially_discovered: 'text-warn border-warn/40 bg-warn/5',
};

export const WorldMonitor: React.FC = () => {
  const [targets, setTargets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [base, setBase] = useState('');
  const [api, setApi] = useState('');
  const [openapi, setOpenapi] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [inventory, setInventory] = useState<Record<number, any[]>>({});

  const fetchTargets = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await apiFetch('/world-monitor/targets');
      if (res.ok) {
        const data = await res.json();
        setTargets(Array.isArray(data) ? data : []);
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load World Monitor targets.');
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  };

  const register = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!base.trim()) return;
    setSaveError('');
    setSaving(true);
    const body: Record<string, string> = { base_url: base.trim() };
    if (api.trim()) body.api_base_url = api.trim();
    if (openapi.trim()) body.openapi_url = openapi.trim();
    try {
      const res = await apiFetch('/world-monitor/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        setBase('');
        setApi('');
        setOpenapi('');
        setShowNew(false);
        await fetchTargets();
      } else {
        const errData = await res.json().catch(() => null);
        const detail =
          typeof errData?.detail === 'string' ? errData.detail : errData?.detail?.[0]?.msg || 'Could not register deployment.';
        setSaveError(detail);
      }
    } catch {
      setSaveError('Server connection failed.');
    } finally {
      setSaving(false);
    }
  };

  const runAction = async (id: number, action: 'check' | 'discover') => {
    setBusy(id);
    try {
      const res = await apiFetch(`/world-monitor/targets/${id}/${action}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setTargets((prev) => prev.map((t) => (t.id === id ? data : t)));
        if (data.status === 'discovered' || data.status === 'partially_discovered') {
          refreshInventory(id);
        }
      }
    } catch {
      setError('Action failed: server unreachable.');
    } finally {
      setBusy(null);
    }
  };

  const deleteTarget = async (id: number) => {
    try {
      const res = await apiFetch(`/world-monitor/targets/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setTargets((prev) => prev.filter((t) => t.id !== id));
        setExpanded((prev) => (prev === id ? null : prev));
      }
    } catch {
      setError('Delete failed: server unreachable.');
    }
  };

  const refreshInventory = async (id: number) => {
    try {
      const res = await apiFetch(`/world-monitor/targets/${id}/inventory`);
      if (res.ok) {
        const data = await res.json();
        setInventory((prev) => ({ ...prev, [id]: Array.isArray(data?.endpoints) ? data.endpoints : [] }));
      }
    } catch {
      /* ignore */
    }
  };

  const toggleExpand = (id: number) => {
    const next = expanded === id ? null : id;
    setExpanded(next);
    if (next !== null) refreshInventory(id);
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / World Monitor"
        title="World Monitor"
        description="Registered deployments are assessed as authorized targets. Connectivity is described honestly — reachable, uncovering, or unavailable — never a false verdict."
        actions={
          <Button size="sm" onClick={() => setShowNew((v) => !v)}>
            <Plus className="w-3.5 h-3.5" aria-hidden="true" />
            Register deployment
          </Button>
        }
      />

      {error && (
        <div className="flex items-start gap-2 rounded-xl border border-critical/35 bg-critical/[0.06] px-3.5 py-3 text-[11.5px] text-critical">
          <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      {showNew && (
        <form onSubmit={register} className="panel space-y-3 p-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Input label="Base URL" placeholder="http://127.0.0.1:9000" value={base} onChange={(e) => setBase(e.target.value)} disabled={saving} autoComplete="off" spellCheck={false} />
            <Input label="API base URL (optional)" placeholder="http://127.0.0.1:9000/api" value={api} onChange={(e) => setApi(e.target.value)} disabled={saving} autoComplete="off" spellCheck={false} />
            <Input label="OpenAPI URL (optional)" placeholder="http://127.0.0.1:9000/openapi.json" value={openapi} onChange={(e) => setOpenapi(e.target.value)} disabled={saving} autoComplete="off" spellCheck={false} />
          </div>
          {saveError && <p className="text-[11px] text-critical">{saveError}</p>}
          <Button type="submit" variant="primary" disabled={saving || !base.trim()}>
            {saving ? 'Registering…' : 'Register deployment'}
          </Button>
        </form>
      )}

      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i} className="skeleton h-24 rounded-2xl" />
          ))}
        </div>
      ) : targets.length === 0 ? (
        <EmptyState
          icon={<Globe className="w-4 h-4" aria-hidden="true" />}
          title="No deployments registered"
          description="Register a World Monitor instance to check reachability and discover its API inventory."
        />
      ) : (
        <div className="space-y-3">
          {targets.map((t) => (
            <div key={t.id} className="panel overflow-hidden">
              <div className="flex flex-wrap items-center gap-3 p-4">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[12px] text-text break-all">{t.base_url}</span>
                    <span className={`mono-cell rounded-full border px-2 py-0.5 text-[9.5px] uppercase tracking-wide ${WM_TONES[t.status] || 'text-faint border-line'}`}>
                      {String(t.status || 'not_configured').replace('_', ' ')}
                    </span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-faint">
                    <span>#{t.id}</span>
                    {t.discovered_version && <span>version: {t.discovered_version}</span>}
                    {t.last_checked_at && <span>checked: {formatDateTime(t.last_checked_at)}</span>}
                    {t.api_endpoints_total > 0 && <span>{t.api_endpoints_total} endpoints</span>}
                    {t.staleness && (
                      <span
                        className={`mono-cell rounded-full border px-2 py-0.5 text-[9.5px] ${
                          t.staleness.state === 'fresh'
                            ? 'border-accent/40 text-accent bg-accent/5'
                            : t.staleness.state === 'stale'
                            ? 'border-warn/40 text-medium bg-warn/5'
                            : 'border-line text-faint'
                        }`}
                      >
                        {String(t.staleness.state || 'never_checked').replace('_', ' ')}
                      </span>
                    )}
                    {Array.isArray(t.bridged_scans) && t.bridged_scans.length > 0 && (
                      <span className="mono-cell text-[9.5px] text-accent">
                        bridged to scan(s): {t.bridged_scans.map((s: number) => `#${s}`).join(', ')}
                      </span>
                    )}
                  </div>
                  {t.staleness && t.staleness.state === 'stale' && (
                    <p className="mono-cell text-[9.5px] text-medium mt-1">
                      last health check {t.staleness.seconds_since_last_check != null ? `${t.staleness.seconds_since_last_check}s` : '—'} ago
                      {t.staleness.threshold_seconds ? ` · stale after ${t.staleness.threshold_seconds}s` : ''} — re-probe only on demand
                    </p>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    onClick={() => runAction(t.id, 'check')}
                    disabled={busy === t.id}
                    className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3 h-3 ${busy === t.id ? 'animate-spin' : ''}`} aria-hidden="true" />
                    Health check
                  </button>
                  <button
                    onClick={() => runAction(t.id, 'discover')}
                    disabled={busy === t.id}
                    className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3 py-1.5 text-[11px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20 disabled:opacity-50"
                  >
                    <ScanSearch className={`w-3 h-3 ${busy === t.id ? 'animate-pulse' : ''}`} aria-hidden="true" />
                    Discover
                  </button>
                  <button
                    onClick={() => toggleExpand(t.id)}
                    className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[11px] text-muted transition-colors duration-500 ease-spring hover:bg-surface-2 hover:text-text"
                  >
                    <Blocks className="w-3 h-3" aria-hidden="true" />
                    {expanded === t.id ? 'Collapse' : 'Inventory'}
                  </button>
                  <button
                    onClick={() => deleteTarget(t.id)}
                    className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-critical/30 px-3 py-1.5 text-[11px] text-critical transition-colors duration-500 ease-spring hover:bg-critical/[0.08]"
                    aria-label="Delete deployment"
                  >
                    <Trash2 className="w-3 h-3" aria-hidden="true" />
                  </button>
                </div>
              </div>

              {t.health && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 border-t border-line px-4 py-3">
                  <HealthCell label="Reachable" value={t.health.reachable === true ? 'Yes' : 'No'} ok={t.health.reachable === true} />
                  <HealthCell label="HTTP" value={String(t.health.http_status ?? '—')} />
                  <HealthCell label="Server" value={t.health.server || '—'} />
                  <HealthCell label="Latency" value={t.health.elapsed_ms != null ? `${t.health.elapsed_ms}ms` : '—'} />
                </div>
              )}

              {t.discovery && t.discovery.steps?.length > 0 && (
                <div className="border-t border-line px-4 py-3">
                  <p className="eyebrow mb-2">Discovery ledger ({t.discovery.step_count} steps)</p>
                  <div className="space-y-1">
                    {t.discovery.steps.map((s: any) => (
                      <div key={s.order} className="flex items-start gap-2 text-[10.5px] font-mono">
                        <span className="text-faint shrink-0">#{s.order}</span>
                        <span className="shrink-0 text-muted">{s.source}</span>
                        <span className={`shrink-0 ${s.status === 'completed' ? 'text-accent' : 'text-warn'}`}>{s.status}</span>
                        <span className="text-faint truncate" title={s.detail || ''}>{s.detail || ''}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {expanded === t.id && (
                <div className="border-t border-line px-4 py-3">
                  <p className="eyebrow mb-2">Discovered endpoints</p>
                  {(inventory[t.id] || []).length === 0 ? (
                    <p className="text-[11px] text-faint">No endpoints discovered yet — run Discover to map the deployment end-to-end.</p>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 max-h-72 overflow-y-auto">
                      {(inventory[t.id] || []).map((ep) => (
                        <div key={`${ep.method}-${ep.path}-${ep.id}`} className="flex items-center gap-2 rounded-lg border border-line px-2.5 py-1.5">
                          <span className={`mono-cell text-[9.5px] shrink-0 ${ep.method === 'GET' ? 'text-accent' : 'text-muted'}`}>
                            {ep.method}
                          </span>
                          <span className="font-mono text-[10px] text-muted truncate" title={ep.path}>{ep.path}</span>
                          {ep.authentication_hint && (
                            <span className="mono-cell text-[9px] text-faint ml-auto shrink-0">{ep.authentication_hint}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const HealthCell: React.FC<{ label: string; value: string; ok?: boolean }> = ({ label, value, ok }) => (
  <div className="rounded-xl border border-line px-3 py-2">
    <p className="eyebrow">{label}</p>
    <p className={`mt-0.5 flex items-center gap-1.5 text-[12px] font-medium ${ok !== undefined ? (ok ? 'text-accent' : 'text-critical') : 'text-text'}`}>
      {ok !== undefined && (ok ? <CheckCircle2 className="w-3 h-3" aria-hidden="true" /> : <XCircle className="w-3 h-3" aria-hidden="true" />)}
      {ok !== undefined && value === '' ? '—' : value || '—'}
    </p>
  </div>
);

export default WorldMonitor;