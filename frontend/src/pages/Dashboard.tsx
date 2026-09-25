import React, { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, Footprints, Network, ShieldCheck, Target } from 'lucide-react';
import { apiFetch, getScanCoverage } from '../api';
import type { SurfaceCoverage } from '../api';
import { DashboardHeader } from '../components/dashboard/DashboardHeader';
import { PostureCard } from '../components/dashboard/PostureCard';
import { MetricCard } from '../components/dashboard/MetricCard';
import { SurfaceCard } from '../components/dashboard/SurfaceCard';
import { ChartCard } from '../components/dashboard/ChartCard';
import { SecurityScoreTrend } from '../components/dashboard/SecurityScoreTrend';
import { SeverityDistribution } from '../components/dashboard/SeverityDistribution';
import { FindingsLifecyclePanel } from '../components/dashboard/FindingsLifecyclePanel';
import { ObservationsGrid } from '../components/dashboard/ObservationsGrid';
import { RecentAssessments, type RecentScanRow } from '../components/dashboard/RecentAssessments';

export const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [agg, setAgg] = useState<any>(null);
  const [surface, setSurface] = useState<SurfaceCoverage | null>(null);
  const [latestScanId, setLatestScanId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [scanRes, summaryRes, aggRes] = await Promise.all([
        apiFetch('/scans/list'),
        apiFetch('/scans/summary'),
        apiFetch('/dashboard/summary'),
      ]);
      if (scanRes.ok) {
        const rows = await scanRes.json();
        setScans(rows);
        setError('');
        const latest = [...rows].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
        if (latest) {
          setLatestScanId(latest.id);
          const cov = await getScanCoverage(latest.id);
          setSurface(cov?.surface ?? null);
        } else {
          setLatestScanId(null);
          setSurface(null);
        }
      } else if (!summaryRes.ok) {
        const errData = await summaryRes.json().catch(() => null);
        setError(errData?.detail || 'Failed to load assessment data.');
      }
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
      if (aggRes.ok) {
        setAgg(await aggRes.json());
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const latestScans = (raw: any[], count = 6) =>
    [...raw].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, count);

  const coverageByScan = new Map<number, number>();
  (agg?.coverage_trend ?? []).forEach((t: any) => {
    if (t?.coverage !== null && t?.coverage !== undefined) {
      coverageByScan.set(Number(t.scan_id), Number(t.coverage));
    }
  });

  const latestScan = [...scans].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];

  const recentRows: RecentScanRow[] = latestScans(scans).map((s: any) => ({
    id: s.id,
    target: s.target,
    status: s.status,
    security_score: s.security_score,
    coverage: coverageByScan.get(s.id) ?? null,
    observations: agg?.observations_by_scan?.[String(s.id)] ?? null,
    created_at: s.created_at,
  }));

  return (
    <div className="flex flex-col gap-6">
      <DashboardHeader
        assessmentsCount={scans.length}
        latestStatus={latestScan?.status ?? null}
        latestCreatedAt={latestScan?.created_at ?? null}
      />

      {/* Summary / posture grid */}
      <section
        className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-[minmax(0,2.4fr)_repeat(3,minmax(0,1fr))]"
        aria-label="Security posture summary"
      >
        <PostureCard
          confirmedFindings={agg?.confirmed_findings}
          candidateFindings={agg?.candidate_findings}
          observationCount={agg?.observation_count}
          assetsTotal={agg?.assets_total}
          assessmentsTotal={agg?.scans_total ?? scans.length}
          loading={loading}
          className="sm:col-span-2 xl:col-span-1"
        />
        <div className="grid gap-4 sm:col-span-2 sm:grid-cols-3 xl:col-span-3">
          <MetricCard
            label="Assessments run"
            icon={<Target className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            value={agg?.scans_total ?? scans.length}
            note="persisted scan ledger"
            loading={loading}
            to="/scans"
          />
          <MetricCard
            label="Open findings"
            icon={<AlertTriangle className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            value={summary?.open_findings}
            note="awaiting resolution"
            loading={loading}
            to="/findings"
            iconTone="text-critical"
          />
          <MetricCard
            label="Validated findings"
            icon={<ShieldCheck className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            value={agg?.confirmed_findings}
            note="evidence-validated"
            loading={loading}
            to="/findings"
            valueTone="text-accent"
          />
        </div>
      </section>

      {/* Surface / evidence grid */}
      <section
        className="grid grid-cols-1 gap-4 md:grid-cols-[minmax(0,2.2fr)_minmax(220px,0.8fr)]"
        aria-label="Attack surface and evidence"
      >
        <SurfaceCard latestScanId={latestScanId} surface={surface} loading={loading} />
        <div className="grid grid-cols-2 gap-4 md:grid-cols-1 md:grid-rows-2">
          <MetricCard
            label="Evidence record"
            icon={<Footprints className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            value={agg?.observation_count}
            note="persisted observations"
            loading={loading}
            to="/coverage"
          />
          <MetricCard
            label="Open ports"
            icon={<Network className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />}
            value={summary?.open_ports_total}
            note={`${summary?.open_ports?.length ?? 0} distinct ports tracked`}
            loading={loading}
            to="/surface"
            iconTone="text-low"
          />
        </div>
      </section>

      {/* Chart grid */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-2" aria-label="Security analytics">
        <ChartCard
          title="Security score trend"
          meta="last assessments"
          note="Scores are computed in the backend from confirmed findings only — starting at 100 and deducting per evidence-backed issue. It is a findings-derived posture signal, not a coverage statistic."
        >
          <SecurityScoreTrend history={summary?.score_history ?? null} loading={loading} />
        </ChartCard>
        <ChartCard title="Severity distribution" meta="open findings">
          <SeverityDistribution dist={summary?.severity_distribution ?? null} loading={loading} />
        </ChartCard>
      </section>

      {/* Findings lifecycle + coverage */}
      <FindingsLifecyclePanel
        lifecycle={agg?.findings_lifecycle}
        coverageTrend={agg?.coverage_trend}
        openFindings={summary?.open_findings}
        confirmedFindings={agg?.confirmed_findings}
        remediated={agg?.findings_lifecycle?.remediated}
        loading={loading}
      />

      {/* Observations (evidence chain) */}
      <ObservationsGrid
        byScan={agg?.observations_by_scan}
        scans={scans}
        observationCount={agg?.observation_count}
        assetsTotal={agg?.assets_total}
        loading={loading}
      />

      {/* Recent assessments */}
      <RecentAssessments
        rows={recentRows}
        rowCount={scans.length}
        loading={loading}
        error={error}
        onRetry={fetchData}
      />
    </div>
  );
};