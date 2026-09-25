import React, { useState, useEffect, useCallback } from 'react';
import {
  CalendarClock,
  CalendarPlus,
  Play,
  Pencil,
  Trash2,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Clock,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  listSchedules,
  createSchedule,
  updateSchedule,
  deleteSchedule,
  runSchedule,
  getScheduleScans,
} from '../api';
import type { ScheduleRow, ScheduleScanRow } from '../api';
import { PageHeader } from '../components/PageHeader';
import { EmptyState } from '../components/EmptyState';
import { SkeletonTable, SkeletonPanel } from '../components/Skeleton';
import { StatusBadge } from '../components/StatusBadge';
import { DataTable } from '../components/DataTable';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { formatDateTime, relativeTime } from '../components/format';

type Notice = { kind: 'error' | 'ok' | 'warn'; message: string } | null;

const CADENCE_UNITS: Record<string, string> = { hourly: 'hour', daily: 'day', weekly: 'week' };
const CADENCE_OPTIONS = [
  { value: 'hourly', label: 'Hourly' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
];

const cadenceLabel = (c: string, i: number) => {
  const unit = CADENCE_UNITS[c] ?? 'period';
  return `Every ${i} ${unit}${i > 1 ? 's' : ''}`;
};

export const Schedules: React.FC = () => {
  const [schedules, setSchedules] = useState<ScheduleRow[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice>(null);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<ScheduleRow | null>(null);
  const [target, setTarget] = useState('');
  const [name, setName] = useState('');
  const [cadence, setCadence] = useState<'hourly' | 'daily' | 'weekly'>('daily');
  const [interval, setInterval] = useState(1);
  const [enabled, setEnabled] = useState(true);
  const [formBusy, setFormBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [runTarget, setRunTarget] = useState<ScheduleRow | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ScheduleRow | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const [expandId, setExpandId] = useState<number | null>(null);
  const [scansBySchedule, setScansBySchedule] = useState<Record<number, ScheduleScanRow[]>>({});
  const [scansLoading, setScansLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const rows = await listSchedules();
    setSchedules(rows ?? []);
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const setNoticeSoon = (n: Notice) => {
    setNotice(n);
    if (n) {
      window.setTimeout(() => setNotice(null), 8000);
    }
  };

  const openCreate = () => {
    setEditing(null);
    setTarget('');
    setName('');
    setCadence('daily');
    setInterval(1);
    setEnabled(true);
    setFormError(null);
    setFormOpen(true);
  };

  const openEdit = (s: ScheduleRow) => {
    setEditing(s);
    setName(s.name ?? '');
    setCadence(s.cadence);
    setInterval(s.interval);
    setFormError(null);
    setFormOpen(true);
  };

  const submitForm = async () => {
    if (editing) {
      if (name.trim() === '') {
        setFormError('Name is required for an edit.');
        return;
      }
      const res = await updateSchedule(editing.id, {
        name: name.trim(),
        cadence,
        interval,
      });
      if (!res.ok) {
        setFormError(`Update failed (${res.error.status ?? 'error'}).`);
        return;
      }
      setSchedules((prev) => prev?.map((p) => (p.id === res.data.id ? res.data : p)) ?? prev);
      setFormOpen(false);
      setNoticeSoon({ kind: 'ok', message: `Schedule #${res.data.id} updated.` });
      return;
    }
    if (target.trim() === '') {
      setFormError('Target is required.');
      return;
    }
    setFormBusy(true);
    const res = await createSchedule({
      target: target.trim(),
      name: name.trim() || null,
      cadence,
      interval,
      enabled,
    });
    setFormBusy(false);
    if (!res.ok) {
      const detail =
        res.error.detail && typeof res.error.detail === 'object' && 'detail' in (res.error.detail as object)
          ? String((res.error.detail as { detail?: unknown }).detail ?? '')
          : '';
      setFormError(
        res.error.status === 403
          ? 'Target is outside the authorized scope for this project.'
          : detail || `Create failed (${res.error.status ?? 'error'}). ${res.error.message}`,
      );
      return;
    }
    setSchedules((prev) => [...(prev ?? []), res.data]);
    setFormOpen(false);
    setNoticeSoon({ kind: 'ok', message: `Schedule created for ${res.data.target}.` });
  };

  const toggleEnabled = async (s: ScheduleRow) => {
    setBusyKey(`toggle-${s.id}`);
    const res = await updateSchedule(s.id, { enabled: !s.enabled });
    setBusyKey(null);
    if (!res.ok) {
      setNoticeSoon({ kind: 'error', message: `Could not ${s.enabled ? 'disable' : 'enable'} schedule.` });
      return;
    }
    setSchedules((prev) => prev?.map((p) => (p.id === res.data.id ? res.data : p)) ?? prev);
  };

  const confirmRun = async () => {
    if (!runTarget) return;
    setBusyKey(`run-${runTarget.id}`);
    const res = await runSchedule(runTarget.id);
    setBusyKey(null);
    if (!res.ok) {
      let m = `Run failed (${res.error.status ?? 'error'}).`;
      if (res.error.status === 409) m = 'Previous run is still in progress; wait for it to finish.';
      if (res.error.status === 403) m = 'Target drifted outside the authorized scope.';
      setNoticeSoon({ kind: 'warn', message: m });
      setRunTarget(null);
      return;
    }
    setNoticeSoon({ kind: 'ok', message: `Run enqueued as assessment #${res.data.scan_id}.` });
    setSchedules((prev) =>
      prev?.map((p) =>
        p.id === res.data.schedule_id
          ? { ...p, last_scan_id: res.data.scan_id, last_run_status: 'queued', last_run_at: new Date().toISOString() }
          : p,
      ) ?? prev,
    );
    setRunTarget(null);
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setBusyKey(`delete-${deleteTarget.id}`);
    const res = await deleteSchedule(deleteTarget.id);
    setBusyKey(null);
    if (!res.ok) {
      setNoticeSoon({ kind: 'error', message: `Delete failed (${res.error.status ?? 'error'}).` });
      setDeleteTarget(null);
      return;
    }
    setSchedules((prev) => prev?.filter((p) => p.id !== deleteTarget.id) ?? prev);
    setNoticeSoon({ kind: 'ok', message: `Schedule ${deleteTarget.name ?? deleteTarget.target} disabled and removed.` });
    setDeleteTarget(null);
  };

  const toggleExpand = async (id: number) => {
    if (expandId === id) {
      setExpandId(null);
      return;
    }
    setExpandId(id);
    if (scansBySchedule[id] === undefined) {
      setScansLoading(true);
      const rows = await getScheduleScans(id);
      setScansBySchedule((prev) => ({ ...prev, [id]: rows ?? [] }));
      setScansLoading(false);
    }
  };

  const expanded = schedules?.find((s) => s.id === expandId) ?? null;
  const expandedScans = expandId !== null ? (scansBySchedule[expandId] ?? null) : null;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Schedules"
        title="Recurring assessments"
        description="Operator-defined recurrent scans. Run-now enqueues a fresh assessment through the same path as the scheduler; delete disables the schedule but keeps all scans it produced. Every run is persisted — never fabricated."
        actions={
          <button
            type="button"
            onClick={openCreate}
            className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3.5 py-1.5 text-[11.5px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20"
          >
            <CalendarPlus className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
            New schedule
          </button>
        }
      />

      {notice && (
        <div
          role="status"
          className={`rounded-2xl border px-4 py-3 text-[12px] leading-relaxed ${
            notice.kind === 'error'
              ? 'border-critical/30 bg-critical/[0.06] text-critical'
              : notice.kind === 'warn'
              ? 'border-medium/30 bg-medium/[0.06] text-medium'
              : 'border-accent/30 bg-accent/[0.06] text-accent'
          }`}
        >
          {notice.message}
        </div>
      )}

      {formOpen && (
        <section className="panel p-5">
          <h2 className="mb-4 flex items-center gap-2 text-[12.5px] font-semibold text-text">
            <CalendarPlus className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
            {editing ? `Edit schedule #${editing.id}` : 'Create a recurrent assessment'}
          </h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {!editing && (
              <label className="block">
                <span className="eyebrow mb-1.5 block">Target</span>
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com"
                  className="h-10 w-full rounded-xl border border-line bg-surface-2 px-3 font-mono text-[11.5px] text-text outline-none transition-colors duration-500 ease-spring placeholder:text-faint focus:border-accent"
                />
              </label>
            )}
            <label className="block">
              <span className="eyebrow mb-1.5 block">Name</span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={editing ? `Schedule #${editing.id}` : 'optional label'}
                className="h-10 w-full rounded-xl border border-line bg-surface-2 px-3 text-[11.5px] text-text outline-none transition-colors duration-500 ease-spring placeholder:text-faint focus:border-accent"
              />
            </label>
            <label className="block">
              <span className="eyebrow mb-1.5 block">Cadence</span>
              <select
                value={cadence}
                onChange={(e) => setCadence(e.target.value as typeof cadence)}
                className="h-10 w-full cursor-pointer appearance-none rounded-xl border border-line bg-surface-2 px-3 text-[11.5px] text-text outline-none transition-colors duration-500 ease-spring focus:border-accent"
              >
                {CADENCE_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="eyebrow mb-1.5 block">
                Interval — {cadenceLabel(cadence, interval)}
              </span>
              <input
                type="number"
                min={1}
                max={90}
                value={interval}
                onChange={(e) => setInterval(Math.max(1, Math.min(90, Number(e.target.value) || 1)))}
                className="h-10 w-full rounded-xl border border-line bg-surface-2 px-3 font-mono text-[11.5px] text-text outline-none transition-colors duration-500 ease-spring focus:border-accent"
              />
            </label>
            {!editing && (
              <label className="flex items-end gap-2 pb-1">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                  className="h-4 w-4 accent-[#e8ff3d]"
                />
                <span className="text-[11.5px] text-muted">Enabled immediately</span>
              </label>
            )}
          </div>
          {formError && (
            <p role="alert" className="mt-3 text-[11.5px] text-critical">
              {formError}
            </p>
          )}
          <div className="mt-4 flex items-center gap-2">
            <button
              type="button"
              onClick={() => void submitForm()}
              disabled={formBusy}
              className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3.5 py-1.5 text-[11.5px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20 disabled:opacity-50"
            >
              {formBusy && <RefreshCw className="h-3 w-3 animate-spin" strokeWidth={1.5} aria-hidden="true" />}
              {editing ? 'Save changes' : 'Create schedule'}
            </button>
            <button
              type="button"
              onClick={() => setFormOpen(false)}
              disabled={formBusy}
              className="rounded-full border border-line px-3.5 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:text-text disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </section>
      )}

      {loading ? (
        <SkeletonTable rows={4} cols={5} />
      ) : schedules?.length === 0 ? (
        <EmptyState
          icon={<CalendarClock className="h-4 w-4" aria-hidden="true" />}
          title="No schedules yet"
          description="A schedule enqueues a fresh assessment at its cadence. Creation requires the target to be inside your authorized scope."
          action={
            <button
              type="button"
              onClick={openCreate}
              className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3.5 py-1.5 text-[11.5px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20"
            >
              <CalendarPlus className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
              Create a schedule
            </button>
          }
        />
      ) : (
        <>
          <section className="panel overflow-hidden">
            <DataTable
              rows={schedules}
              keyField={(s: ScheduleRow) => String(s.id)}
              empty={{ title: 'No schedules', description: 'Create one to begin recurring assessments.' }}
              columns={[
                {
                  key: 'schedule',
                  label: 'Schedule',
                  render: (s: ScheduleRow) => (
                    <div className="minw-0">
                      <p className="truncate text-[12px] font-medium text-text">
                        {s.name ?? `Schedule #${s.id}`}
                      </p>
                      <p className="mono-cell mt-0.5 max-w-[260px] truncate text-[10px] text-faint">{s.target}</p>
                    </div>
                  ),
                },
                {
                  key: 'cadence',
                  label: 'Cadence',
                  render: (s: ScheduleRow) => (
                    <span className="mono-cell text-[10.5px] text-muted">{cadenceLabel(s.cadence, s.interval)}</span>
                  ),
                },
                {
                  key: 'next_run',
                  label: 'Next run',
                  render: (s: ScheduleRow) => (
                    <span className="mono-cell text-[10.5px] text-faint">
                      {s.enabled ? formatDateTime(s.next_run_at) : 'disabled'}
                    </span>
                  ),
                },
                {
                  key: 'last_run',
                  label: 'Last run',
                  render: (s: ScheduleRow) => (
                    <div className="minw-0">
                      {s.last_run_at ? (
                        <>
                          <span className="mono-cell text-[10.5px] text-muted">{relativeTime(s.last_run_at)}</span>
                          {s.last_scan_id ? (
                            <Link to={`/scans/${s.last_scan_id}`} className="soft-link ml-2 block text-[10px]">
                              #{s.last_scan_id}
                            </Link>
                          ) : null}
                        </>
                      ) : (
                        <span className="text-[10px] text-faint">never</span>
                      )}
                      {s.last_run_status && <StatusBadge status={s.last_run_status} />}
                    </div>
                  ),
                },
                {
                  key: 'enabled',
                  label: 'Enabled',
                  render: (s: ScheduleRow) => (
                    <button
                      type="button"
                      onClick={() => void toggleEnabled(s)}
                      disabled={busyKey === `toggle-${s.id}`}
                      className="cursor-pointer rounded-full border border-line px-3 py-1 text-[10.5px] transition-colors duration-500 ease-spring hover:border-line-strong disabled:opacity-50"
                      aria-pressed={s.enabled}
                    >
                      {s.enabled ? (
                        <span className="flex items-center gap-1.5 text-accent">
                          <span className="dot dot-ok" aria-hidden="true" /> on
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-faint">
                          <span className="dot dot-neutral" aria-hidden="true" /> off
                        </span>
                      )}
                    </button>
                  ),
                },
                {
                  key: 'actions',
                  label: 'Actions',
                  render: (s: ScheduleRow) => (
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => setRunTarget(s)}
                        disabled={!s.enabled || busyKey === `run-${s.id}`}
                        title="Run now"
                        className="rounded-full border border-line p-1.5 text-muted transition-colors duration-500 ease-spring hover:border-accent/40 hover:text-accent disabled:opacity-40"
                      >
                        <Play className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        onClick={() => openEdit(s)}
                        title="Edit cadence or name"
                        className="rounded-full border border-line p-1.5 text-muted transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text"
                      >
                        <Pencil className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        onClick={() => setDeleteTarget(s)}
                        title="Delete schedule"
                        className="rounded-full border border-line p-1.5 text-muted transition-colors duration-500 ease-spring hover:border-critical/40 hover:text-critical"
                      >
                        <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        onClick={() => void toggleExpand(s.id)}
                        title={expandId === s.id ? 'Hide scans' : 'Show scans from this schedule'}
                        className="rounded-full border border-line p-1.5 text-muted transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text"
                        aria-expanded={expandId === s.id}
                      >
                        {expandId === s.id ? (
                          <ChevronDown className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
                        )}
                      </button>
                    </div>
                  ),
                },
              ]}
            />

            {expanded && (
              <div className="border-t border-line px-5 py-4">
                <h3 className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-faint">
                  <Clock className="h-3 w-3" aria-hidden="true" />
                  Assessments produced by {expanded.name ?? `schedule #${expanded.id}`}
                </h3>
                {scansLoading ? (
                  <SkeletonPanel className="min-h-[90px]" />
                ) : expandedScans === null ? null : expandedScans.length === 0 ? (
                  <p className="text-[11px] text-faint">No assessments have run from this schedule yet.</p>
                ) : (
                  <ul className="space-y-1">
                    {expandedScans.map((sc) => (
                      <li key={sc.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-line bg-surface-2/50 px-3 py-2">
                        <Link to={`/scans/${sc.id}/timeline`} className="soft-link mono-cell text-[10.5px] text-text">
                          #{sc.id}
                        </Link>
                        <span className="mono-cell max-w-[220px] truncate text-[10px] text-faint">{sc.target}</span>
                        <span className="mono-cell text-[9.5px] text-faint">{sc.stage}</span>
                        <StatusBadge status={sc.status} />
                        <span className="mono-cell ml-auto text-[9.5px] text-faint">{formatDateTime(sc.created_at)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </section>

          <p className="text-[10px] leading-relaxed text-faint">
            Schedules use persisted next-run calculations: the backend scheduler enqueues each due schedule through
            `_enqueue_from_schedule`. Run-now uses the same path with `trigger="run_now"` and never advances the
            cadence.
          </p>
        </>
      )}

      <ConfirmDialog
        open={runTarget !== null}
        title="Run this schedule now?"
        body={
          runTarget ? (
            <>
              <span className="mono-cell text-accent">{runTarget.target}</span> will queue a fresh assessment
              immediately. Blocked while a previous run is still in progress, or if the target has drifted out of
              scope.
            </>
          ) : null
        }
        confirmLabel={busyKey === `run-${runTarget?.id}` ? 'Queuing…' : 'Run now'}
        busy={busyKey === `run-${runTarget?.id}`}
        backdropLabel="Run schedule now"
        onConfirm={() => void confirmRun()}
        onCancel={() => setRunTarget(null)}
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete schedule?"
        tone="danger"
        body={
          deleteTarget ? (
            <>
              This disables and removes {deleteTarget.name ?? `schedule ${deleteTarget.target}`} from the list. All
              assessments it already produced are kept.
            </>
          ) : null
        }
        confirmLabel={busyKey === `delete-${deleteTarget?.id}` ? 'Deleting…' : 'Delete schedule'}
        busy={busyKey === `delete-${deleteTarget?.id}`}
        backdropLabel="Delete schedule"
        onConfirm={() => void confirmDelete()}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
};

export default Schedules;