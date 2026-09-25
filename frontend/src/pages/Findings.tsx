import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import {
  ShieldAlert,
  Filter,
  FlaskConical,
  GitCommitHorizontal,
  ShieldCheck,
  ScanLine,
} from 'lucide-react';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { DataTable } from '../components/DataTable';
import { SeverityBadge } from '../components/SeverityBadge';
import { DetailDrawer } from '../components/DetailDrawer';
import { MonospaceValue } from '../components/MonospaceValue';
import { CopyButton } from '../components/CopyButton';
import { StatusBadge } from '../components/StatusBadge';
import { SkeletonPanel } from '../components/Skeleton';
import { formatDate, formatDateTime } from '../components/format';

const TRIAGE_ACTIONS = [
  { id: 'confirm', label: 'Confirm' },
  { id: 'false_positive', label: 'False positive' },
  { id: 'duplicate', label: 'Duplicate' },
  { id: 'accepted_risk', label: 'Accepted risk' },
  { id: 'resolve', label: 'Resolve' },
];

const SIH_AREAS: { key: string; label: string }[] = [
  { key: 'authentication', label: 'Authentication & Session Management' },
  { key: 'authorization', label: 'Authorization & Access Control' },
  { key: 'input_validation', label: 'Input Validation & Data Handling' },
  { key: 'api_security', label: 'API Security' },
  { key: 'client_side', label: 'Client-Side Security' },
  { key: 'secure_communication', label: 'Secure Communication (TLS)' },
  { key: 'data_protection', label: 'Data Protection & Privacy' },
];

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const STATUSES = ['confirmed', 'validated', 'candidate', 'rejected', 'duplicate', 'accepted', 'remediated'];

interface Finding {
  id: number;
  scan_id: number;
  target: string | null;
  assessment_type: string | null;
  title: string;
  severity: string;
  status: string;
  state: string;
  category: string | null;
  sih_areas: string[];
  cwe: string | null;
  owasp: string | null;
  endpoint: string | null;
  http_method: string | null;
  parameter: string | null;
  affected_component: string | null;
  confidence: string | null;
  first_seen: string | null;
  last_seen: string | null;
}

const AREA_LABEL: Record<string, string> = Object.fromEntries(SIH_AREAS.map((a) => [a.key, a.label]));

export const Findings: React.FC = () => {
  const [params, setParams] = useSearchParams();
  const [rows, setRows] = useState<Finding[] | null>(null);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);

  const severity = params.get('severity') || '';
  const status = params.get('status') || '';
  const sihArea = params.get('sih_area') || '';

  const fetchFindings = useCallback(async () => {
    setRows(null);
    setError('');
    const qs = new URLSearchParams();
    if (severity) qs.set('severity', severity);
    if (status) qs.set('status', status);
    if (sihArea) qs.set('sih_area', sihArea);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    try {
      const res = await apiFetch(`/findings${suffix}`);
      if (res.ok) {
        const data = await res.json();
        setRows(Array.isArray(data.findings) ? data.findings : []);
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load findings.');
      }
    } catch {
      setError('Server connection failed.');
    }
  }, [severity, status, sihArea]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const handleTriageUpdated = useCallback(() => {
    fetchFindings();
  }, [fetchFindings]);

  const counts = useMemo(() => {
    const base: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    (rows || []).forEach((r) => {
      if (base[r.severity] !== undefined) base[r.severity] += 1;
    });
    return base;
  }, [rows]);

  const activeFilters = [severity && `severity: ${severity}`, status && `status: ${status}`, sihArea && `area: ${AREA_LABEL[sihArea] || sihArea}`]
    .filter(Boolean)
    .length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Assessments / Findings"
        title="Findings"
        description="Every finding across your assessments, derived from persisted evidence. Filter by severity, lifecycle status, or SIH26163 security area. Nothing here is synthesized."
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {SEVERITIES.map((s) => {
          const toneColor =
            s === 'Critical'
              ? 'text-critical'
              : s === 'High'
              ? 'text-high'
              : s === 'Medium'
              ? 'text-medium'
              : s === 'Low'
              ? 'text-low'
              : 'text-neutral';
          const dotColor =
            s === 'Critical'
              ? 'bg-critical'
              : s === 'High'
              ? 'bg-high'
              : s === 'Medium'
              ? 'bg-medium'
              : s === 'Low'
              ? 'bg-low'
              : 'bg-neutral';
          const isSelected = severity === s;
          return (
            <button
              key={s}
              onClick={() => setFilter('severity', isSelected ? '' : s)}
              className={`panel relative overflow-hidden p-4 text-left transition-all duration-300 ${
                isSelected
                  ? 'border-accent/60 bg-accent/[0.04] shadow-[0_0_20px_rgba(232,255,61,0.08)]'
                  : 'hover:border-line-strong'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <p className="eyebrow">{s}</p>
                <span className={`h-2 w-2 rounded-full ${dotColor}`} />
              </div>
              <p className={`tnum text-[26px] font-semibold leading-none tracking-tight ${toneColor}`}>{counts[s]}</p>
            </button>
          );
        })}
      </div>

      <div className="panel flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
        <div className="flex items-center gap-2 text-faint">
          <Filter className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
          <span className="eyebrow">Filters</span>
        </div>
        <select
          value={severity}
          onChange={(e) => setFilter('severity', e.target.value)}
          className="rounded-xl border border-line bg-surface-2 px-3 py-2 text-[12px] text-text"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => setFilter('status', e.target.value)}
          className="rounded-xl border border-line bg-surface-2 px-3 py-2 text-[12px] text-text capitalize"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={sihArea}
          onChange={(e) => setFilter('sih_area', e.target.value)}
          className="rounded-xl border border-line bg-surface-2 px-3 py-2 text-[12px] text-text"
        >
          <option value="">All security areas</option>
          {SIH_AREAS.map((a) => (
            <option key={a.key} value={a.key}>{a.label}</option>
          ))}
        </select>
        {activeFilters > 0 && (
          <button
            onClick={() => setParams(new URLSearchParams(), { replace: true })}
            className="rounded-full border border-line px-3 py-1.5 text-[11px] text-muted transition-colors duration-500 ease-spring hover:text-text"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto mono-cell text-[10px] text-faint">
          {rows === null ? '…' : `${rows.length} shown`}
        </span>
      </div>

      <DataTable
        rows={rows}
        keyField={(r: Finding) => String(r.id)}
        error={error}
        onRetry={fetchFindings}
        onRowClick={(r: Finding) => setSelected(r)}
        empty={{
          title: 'No findings match',
          description: 'Adjust the filters, or run an assessment to produce evidence-backed findings.',
        }}
        columns={[
          {
            key: 'severity',
            label: 'Severity',
            render: (r: Finding) => <SeverityBadge severity={r.severity} />,
          },
          {
            key: 'title',
            label: 'Finding',
            render: (r: Finding) => (
              <div className="min-w-0">
                <p className="truncate text-[12px] text-text">{r.title}</p>
                <p className="mono-cell truncate text-[10px] text-faint">
                  {r.http_method ? `${r.http_method} ` : ''}{r.endpoint || r.affected_component || '—'}
                </p>
              </div>
            ),
          },
          {
            key: 'areas',
            label: 'Security area',
            render: (r: Finding) => (
              <div className="flex flex-wrap gap-1">
                {(r.sih_areas || []).length === 0 ? (
                  <span className="text-faint text-[10.5px]">—</span>
                ) : (
                  r.sih_areas.map((a) => (
                    <span key={a} className="chip !py-0.5 !text-[9.5px]">{AREA_LABEL[a] || a}</span>
                  ))
                )}
              </div>
            ),
          },
          {
            key: 'target',
            label: 'Assessment',
            render: (r: Finding) => (
              <div className="min-w-0">
                <p className="truncate font-mono text-[10.5px] text-muted">{r.target || '—'}</p>
                <p className="mono-cell text-[9.5px] text-faint">
                  {r.assessment_type ? r.assessment_type.replace('_', ' ') : 'assessment'} #{r.scan_id}
                </p>
              </div>
            ),
          },
          {
            key: 'status',
            label: 'Status',
            render: (r: Finding) => (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="mono-cell text-[10px] text-muted capitalize">{(r.status || '').replace('_', ' ')}</span>
                {r.state && r.state !== r.status && (
                  <span className="chip !py-0.5 !text-[9px] !text-faint">{r.state}</span>
                )}
              </div>
            ),
          },
          {
            key: 'first_seen',
            label: 'First seen',
            render: (r: Finding) => (
              <span className="mono-cell text-[10px] text-faint">{formatDate(r.first_seen)}</span>
            ),
          },
        ]}
      />

      <FindingDrawer
        finding={selected}
        open={selected !== null}
        onClose={() => setSelected(null)}
        onUpdated={handleTriageUpdated}
      />
    </div>
  );
};

/* ------------------------------------------------------------------------- */
/* Evidence helpers — everything here renders persisted record fields only.  */
/* ------------------------------------------------------------------------- */

interface IntegrityObject {
  request_ok?: boolean;
  response_ok?: boolean;
}

const integrityTone = (integrity: IntegrityObject | string | null | undefined): string => {
  if (integrity && typeof integrity === 'object') {
    if (integrity.request_ok === true && integrity.response_ok === true) return 'matched';
    if (integrity.request_ok === false || integrity.response_ok === false) return 'mismatched';
    return 'unverified';
  }
  const v = (integrity || '').toLowerCase();
  if (v.includes('match') || v === 'intact') return 'matched';
  if (v.includes('mismatch') || v.includes('failed') || v.includes('break')) return 'mismatched';
  return 'unverified';
};

const integrityLabel = (integrity: IntegrityObject | string | null | undefined): string => {
  if (integrity && typeof integrity === 'object') {
    if (integrity.request_ok === true && integrity.response_ok === true) return 'verified';
    if (integrity.request_ok === false || integrity.response_ok === false) return 'MISMATCH';
    return 'unverified';
  }
  return integrity || 'unverified';
};

const FindingDrawer: React.FC<{
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
  onUpdated?: (id: number) => void;
}> = ({ finding, open, onClose, onUpdated }) => {
  const [activeFinding, setActiveFinding] = useState<Finding | null>(finding);
  const [detail, setDetail] = useState<any | null>(null);
  const [error, setError] = useState('');
  const [triageAction, setTriageAction] = useState<string>('');
  const [triageReason, setTriageReason] = useState('');
  const [triageBusy, setTriageBusy] = useState(false);
  const [triageError, setTriageError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    if (finding) {
      setActiveFinding(finding);
    }
  }, [finding]);

  const currentFinding = finding || activeFinding;

  useEffect(() => {
    if (!currentFinding?.id || !open) return;
    let cancelled = false;
    setDetail(null);
    setError('');
    setTriageError('');
    apiFetch(`/findings/${currentFinding.id}`)
      .then(async (res) => (res.ok ? res.json() : Promise.reject(await res.json().catch(() => null))))
      .then((data) => !cancelled && setDetail(data))
      .catch((err) => !cancelled && setError(err?.detail || 'Failed to load finding detail.'));
    return () => {
      cancelled = true;
    };
  }, [currentFinding?.id, open]);

  const runTriage = async () => {
    if (!triageAction || !currentFinding) return;
    setTriageBusy(true);
    setTriageError('');
    try {
      const res = await apiFetch(`/findings/${currentFinding.id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: triageAction, reason: triageReason || null }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        throw new Error(typeof errData?.detail === 'string' ? errData.detail : 'Triage failed.');
      }
      const data = await res.json();
      setTriageAction('');
      setTriageReason('');
      setDetail((prev: any) => (prev ? { ...prev, status: data.status, state: data.state } : prev));
      onUpdated?.(currentFinding.id);
    } catch (err: any) {
      setTriageError(err.message || 'Triage failed.');
    } finally {
      setTriageBusy(false);
    }
  };

  const openScan = () => {
    if (!currentFinding) return;
    onClose();
    navigate(`/scans/${currentFinding.scan_id}`);
  };

  const poc = detail?.proof_of_concept;
  const cvss = detail?.cvss || {};
  const history = Array.isArray(detail?.history) ? detail.history : [];
  const evidence = Array.isArray(detail?.evidence) ? detail.evidence : [];
  const verifications = Array.isArray(detail?.verifications) ? detail.verifications : [];

  if (!currentFinding) return null;

  return (
    <DetailDrawer
      open={open}
      onClose={onClose}
      title={
        <span className="flex min-w-0 items-center gap-2.5">
          <span className="mono-cell shrink-0 rounded-md border border-line bg-surface-2 px-1.5 py-0.5 text-[9.5px] font-medium text-faint">
            F-{currentFinding.id}
          </span>
          <span className="truncate font-semibold text-text">{currentFinding.title}</span>
        </span>
      }
      footer={
        <div className="flex w-full items-center justify-between gap-3">
          <button
            onClick={openScan}
            className="inline-flex cursor-pointer items-center gap-1.5 rounded-full border border-line bg-surface px-3.5 py-1.5 text-[11.5px] font-medium text-muted transition-colors hover:border-line-strong hover:bg-white/[0.04] hover:text-text"
          >
            <ScanLine className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
            Open assessment
          </button>
          <CopyButton value={`#${currentFinding.id} ${currentFinding.title}`} label="Copy finding ref" />
        </div>
      }
    >
      {error ? (
        <p className="text-[11.5px] text-critical">{error}</p>
      ) : !detail ? (
        <SkeletonPanel className="min-h-[420px]" />
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={currentFinding.severity} />
            <StatusBadge status={currentFinding.status} />
            {currentFinding.state && currentFinding.state !== currentFinding.status && (
              <span className="mono-cell rounded-full border border-line bg-surface-2 px-2.5 py-1 text-[10px] text-faint">
                state: {currentFinding.state}
              </span>
            )}
            {detail.verification_state && (
              <span className="mono-cell rounded-full border border-accent/30 bg-accent/5 px-2 py-1 text-[10px] text-accent">
                {detail.verification_state}
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <KV label="Category" value={detail.category || '—'} mono />
            <KV label="Component" value={detail.affected_component || '—'} mono />
            <KV label="Endpoint" value={detail.endpoint || '—'} mono />
            <KV label="Parameter" value={detail.parameter || '—'} mono />
            <KV label="OWASP" value={detail.owasp || '—'} />
            <KV label="CWE" value={detail.cwe ? `CWE-${detail.cwe}` : '—'} mono />
            {detail.source_test && <KV label="Source test" value={detail.source_test} mono />}
            {detail.source_tool && <KV label="Source tool" value={detail.source_tool} mono />}
          </div>

          {(cvss.vector || cvss.score != null) && (
            <div>
              <p className="eyebrow mb-1.5">CVSS</p>
              <div className="grid grid-cols-2 gap-3">
                <KV label="Score / version" value={cvss.score != null ? `${cvss.score}${cvss.version ? ` (v${cvss.version})` : ''}` : '—'} mono />
                <KV label="Vector" value={cvss.vector || '—'} mono />
              </div>
            </div>
          )}

          {detail.description && (
            <div>
              <p className="eyebrow mb-1">Description</p>
              <p className="leading-relaxed text-muted">{detail.description}</p>
            </div>
          )}

          {(detail.remediation || detail.remediation_details?.technical_fix) && (
            <div>
              <p className="eyebrow mb-1">Recommended remediation</p>
              <p className="leading-relaxed text-accent">{detail.remediation || detail.remediation_details?.technical_fix}</p>
            </div>
          )}

          {detail.validation_reason && (
            <div>
              <p className="eyebrow mb-1">Deterministic validation</p>
              <p className="leading-relaxed text-muted">{detail.validation_reason}</p>
            </div>
          )}

          {poc && poc.request && (
            <div>
              <p className="eyebrow mb-1.5">Proof of concept</p>
              <div className="space-y-1 rounded-xl border border-line p-3 text-[10.5px]">
                <p className="mono-cell text-faint">
                  {poc.request.method} {poc.request.endpoint || ''}
                  {poc.request.parameter ? ` (param: ${poc.request.parameter})` : ''}
                </p>
                <p className="text-muted"><span className="text-faint">expected:</span> {poc.expected_behavior || '—'}</p>
                <p className="text-muted"><span className="text-faint">observed:</span> {poc.observed_behavior || '—'}</p>
              </div>
              {poc.steps_to_reproduce && (
                <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-xl border border-line bg-surface-2 p-3 font-mono text-[10px] text-muted">
                  {poc.steps_to_reproduce}
                </pre>
              )}
            </div>
          )}

          {/* Evidence ledger */}
          <div>
            <p className="eyebrow mb-2">Evidence ledger ({evidence.length})</p>
            {evidence.length === 0 ? (
              <div className="flex items-start gap-2 rounded-xl border border-line p-3 text-[10.5px] text-faint">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" strokeWidth={1.5} aria-hidden="true" />
                <span>No structured evidence records are attached to this finding — it is a ledger/triage entry, not a
                  verified issue.</span>
              </div>
            ) : (
              <div className="space-y-2">
                {evidence.map((e: any, evidenceIdx: number) => {
                  const integrity = integrityTone(e.integrity);
                  const evidenceNo = e.evidence_id ?? e.id ?? evidenceIdx;
                  return (
                    <div key={evidenceNo} className="rounded-xl border border-line p-3 text-[10.5px]">
                      <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
                        <span className="mono-cell rounded-md border border-accent/30 bg-accent/5 px-1.5 py-0.5 text-[9.5px] text-accent">
                          {e.evidence_type}
                        </span>
                        {e.observation_id != null && (
                          <Link to={`/scans/${currentFinding.scan_id}/timeline`} className="soft-link mono-cell text-[9.5px]">
                            observation #{e.observation_id}
                          </Link>
                        )}
                        <span
                          className={`mono-cell rounded-md border px-1.5 py-0.5 text-[9px] ${
                            integrity === 'matched'
                              ? 'border-accent/30 bg-accent/[0.04] text-accent'
                              : integrity === 'mismatched'
                              ? 'border-critical/30 bg-critical/[0.05] text-critical'
                              : 'border-line text-faint'
                          }`}
                        >
                          integrity: {integrityLabel(e.integrity)}
                        </span>
                        <span className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-faint">
                          {e.redaction_status}
                        </span>
                        {e.security_boundary && (
                          <span className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-faint">
                            {e.security_boundary}
                          </span>
                        )}
                        <span className="mono-cell rounded-md border border-line px-1.5 py-0.5 text-[9px] text-faint">
                          #{evidenceNo}
                        </span>
                      </div>
                      <p className="text-muted"><span className="text-faint">expected:</span> {e.expected || '—'}</p>
                      <p className="text-muted"><span className="text-faint">actual:</span> {e.actual || '—'}</p>
                      {e.provenance && (
                        <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-0.5 border-t border-line/60 pt-1.5 text-[9.5px] text-faint">
                          <span className="font-mono text-[9.5px] text-muted">{e.provenance.tool || 'tool'}</span>
                          {e.provenance.stage && <span>· {e.provenance.stage}</span>}
                          {e.provenance.attempt != null && <span>· attempt {e.provenance.attempt}</span>}
                          <span>· {e.provenance.status || 'unknown'}</span>
                          {e.provenance.duration_ms != null && (
                            <span>· {(e.provenance.duration_ms / 1000).toFixed(1)}s</span>
                          )}
                          {e.provenance.exit_code != null && <span>· exit {e.provenance.exit_code}</span>}
                          {e.provenance.execution_id != null && (
                            <span className="soft-link font-mono">exec #{e.provenance.execution_id}</span>
                          )}
                        </div>
                      )}
                      {(e.original_size != null || e.captured_size != null) && (
                        <p className="mt-1 mono-cell text-[9px] text-faint">
                          captured {e.captured_size ?? '—'}B of {e.original_size ?? '—'}B
                          {e.truncated ? ' · truncated' : ''}
                        </p>
                      )}
                      {(e.request_hash || e.response_hash) && (
                        <div className="mt-2 space-y-1 border-t border-line/60 pt-2">
                          {e.request_hash && (
                            <div className="flex items-center gap-2 text-[9.5px] text-faint">
                              <span className="shrink-0">req hash</span>
                              <MonospaceValue value={e.request_hash} copyable copyLabel="Copy request hash" className="text-[9px]" />
                            </div>
                          )}
                          {e.response_hash && (
                            <div className="flex items-center gap-2 text-[9.5px] text-faint">
                              <span className="shrink-0">res hash</span>
                              <MonospaceValue value={e.response_hash} copyable copyLabel="Copy response hash" className="text-[9px]" />
                            </div>
                          )}
                          <p className="text-[9px] leading-relaxed text-faint">
                            Hashes are of redacted capture bodies; `original_size` reflects the pre-redaction store and
                            hash-free captures show as unverified.
                          </p>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Verifications */}
          {verifications.length > 0 && (
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-text">
                <ShieldCheck className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
                Verifications ({verifications.length})
              </p>
              <div className="space-y-1.5">
                {verifications.map((v: any, vi: number) => (
                  <div key={v.id ?? vi} className="rounded-xl border border-line px-3 py-2 text-[10.5px]">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="mono-cell text-[10px] text-muted">{v.method}</span>
                      <StatusBadge status={v.status ?? 'unverified'} />
                      {v.rule_id && <span className="mono-cell text-[9.5px] text-faint">{v.rule_id}</span>}
                      <span className="mono-cell ml-auto text-[9.5px] text-faint">
                        {v.created_at ? formatDateTime(v.created_at) : '—'}
                      </span>
                    </div>
                    {v.condition && <p className="mt-1 mono-cell text-[10px] text-faint">condition: {v.condition}</p>}
                    {v.reason && <p className="mt-1 text-[10px] leading-relaxed text-muted">{v.reason}</p>}
                    {(v.observation_ids?.length ?? 0) > 0 && (
                      <p className="mt-1.5 flex flex-wrap items-center gap-1 text-[9.5px] text-faint">
                        observations:
                        {v.observation_ids.map((oid: number) => (
                          <Link key={oid} to={`/scans/${currentFinding.scan_id}/timeline`} className="soft-link">
                            #{oid}
                          </Link>
                        ))}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <KV label="First seen" value={detail.first_seen ? formatDateTime(detail.first_seen) : '—'} />
            <KV label="Last seen" value={detail.last_seen ? formatDateTime(detail.last_seen) : '—'} />
          </div>

          {/* Verdict history timeline */}
          {history.length > 0 && (
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-text">
                <GitCommitHorizontal className="h-3.5 w-3.5 text-faint" aria-hidden="true" />
                Verdict history
              </p>
              <div className="space-y-1.5">
                {history.map((h: any, hi: number) => (
                  <div
                    key={h.id ?? hi}
                    className="flex items-start gap-2 rounded-xl border border-line px-3 py-2 text-[10.5px]"
                  >
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />
                    <div className="min-w-0 flex-1">
                      <p className="font-mono text-[10px] text-muted">
                        {h.from_status} <span className="text-faint">→</span> {h.to_status}
                        <span className="ml-2 text-faint">by {h.actor || 'system'}</span>
                      </p>
                      <p className="mt-0.5 text-faint">{h.reason || ''}</p>
                      <p className="mt-0.5 text-[9.5px] text-faint">{h.created_at ? formatDateTime(h.created_at) : '—'}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Operator triage */}
          <div className="rounded-xl border border-line p-3">
            <p className="eyebrow mb-2">Operator triage</p>
            <div className="flex flex-wrap gap-1.5">
              {TRIAGE_ACTIONS.map((a) => (
                <button
                  key={a.id}
                  onClick={() => setTriageAction(triageAction === a.id ? '' : a.id)}
                  className={`mono-cell cursor-pointer rounded-full border px-2.5 py-1 text-[10px] transition-colors duration-500 ease-spring ${
                    triageAction === a.id
                      ? 'border-accent/60 bg-accent/10 text-accent'
                      : 'border-line text-faint hover:text-muted'
                  }`}
                  disabled={triageBusy}
                >
                  {a.label}
                </button>
              ))}
            </div>
            {triageAction && (
              <div className="mt-2 space-y-2">
                <input
                  type="text"
                  value={triageReason}
                  onChange={(e) => setTriageReason(e.target.value)}
                  placeholder="Reason (optional, recorded in history)"
                  className="w-full rounded-xl border border-line bg-bg px-3 py-2 text-[11px] text-text placeholder:text-faint/70 focus:border-accent/60 focus:outline-none"
                />
                {triageError && <p className="text-[10.5px] text-critical">{triageError}</p>}
                <button
                  onClick={runTriage}
                  disabled={triageBusy}
                  className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1.5 text-[10.5px] text-accent transition-colors duration-500 ease-spring hover:bg-accent/20 disabled:opacity-50"
                >
                  {triageBusy ? 'Applying…' : `Apply: ${TRIAGE_ACTIONS.find((x) => x.id === triageAction)?.label}`}
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </DetailDrawer>
  );
};

const KV: React.FC<{ label: string; value: string; mono?: boolean }> = ({ label, value, mono }) => (
  <div className="min-w-0 rounded-xl border border-line/60 bg-surface-2/40 p-2.5">
    <p className="eyebrow mb-1 text-[9px] text-faint">{label}</p>
    <p className={`wrap-any break-words text-[11.5px] leading-snug text-text/90 ${mono ? 'font-mono' : ''}`}>{value}</p>
  </div>
);

export default Findings;