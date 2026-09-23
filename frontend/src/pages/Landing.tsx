import React, { useEffect, useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Radar,
  Globe,
  ArrowUpRight,
  ArrowRight,
  ScanLine,
  ShieldCheck,
  FileText,
  Network,
  Boxes,
  Eye,
  Crosshair,
  Fingerprint,
  type LucideIcon,
} from 'lucide-react';
import { motion, AnimatePresence, useScroll, useTransform, useInView, useReducedMotion, useMotionValue, useSpring } from 'framer-motion';
import { Button } from '../components/Button';
import { Reveal } from '../components/Reveal';
import { ResizableNavbarDemo } from '../components/resizable-navbar-demo';

/* ============================================================================
   CyberAgent — public landing (unauthenticated root).
   Editorial acid/lime identity. Every section either states a real product
   capability or is an explicitly-conceptual editorial pipeline visualization.
   NO fabricated findings · NO fake telemetry · NO invented assessments.
   ========================================================================= */

const SECTIONS = [
  { id: 'flow', label: 'Pipeline' },
  { id: 'capabilities', label: 'Capabilities' },
  { id: 'surface', label: 'Attack surface' },
  { id: 'monitor', label: 'World Monitor' },
  { id: 'evidence', label: 'Evidence chain' },
];

const HERO_HOPS: Array<[string, string]> = [
  ['Target', 'World Monitor / custom'],
  ['Discovery', 'hosts / domains'],
  ['Observations', 'raw tool output'],
  ['Evidence', 'persisted records'],
  ['Validation', 'scope + output rules'],
  ['Report', 'fully traceable'],
];

interface Phase {
  label: string;
  sub: string;
  copy: string;
  icon: LucideIcon;
}

const PIPELINE: Phase[] = [
  {
    label: 'Target',
    sub: 'authorized source',
    copy: 'World Monitor deployments or declared custom targets enter the pipeline. Nothing is assessed without authorization.',
    icon: Crosshair,
  },
  {
    label: 'Discovery',
    sub: 'hosts / domains',
    copy: 'Enumerate hosts, domains, subdomains and IPs across declared scope.',
    icon: Radar,
  },
  {
    label: 'Enumeration',
    sub: 'services / ports',
    copy: 'Resolve services, ports and product metadata from live responses.',
    icon: Network,
  },
  {
    label: 'DNS / HTTP',
    sub: 'protocol behavior',
    copy: 'Trace resolution paths and protocol behavior at the boundary.',
    icon: Globe,
  },
  {
    label: 'Observations',
    sub: 'raw tool output',
    copy: 'Every tool output is persisted as a timestamped observation.',
    icon: ScanLine,
  },
  {
    label: 'Evidence',
    sub: 'long-lived records',
    copy: 'Selected observations become immutable evidence records tied to scope, source and tool identity.',
    icon: Boxes,
  },
  {
    label: 'Validation',
    sub: 'scope + output rules',
    copy: 'Deterministic rules confirm the record is in scope and well-formed before any claim.',
    icon: Eye,
  },
  {
    label: 'Finding',
    sub: 'evidence-backed',
    copy: 'Only validated, evidence-backed results surface as findings.',
    icon: ShieldCheck,
  },
  {
    label: 'Report',
    sub: 'fully traceable',
    copy: 'Traceable from source to evidence to finding to report, with a content fingerprint.',
    icon: FileText,
  },
];

const SURFACE = [
  { title: 'Domains & subdomains', copy: 'Scope declares what may be enumerated. Nothing is assessed without authorization.', tags: ['DNS', 'WHOIS', 'subdomains'] },
  { title: 'IPs, ports & services', copy: 'Discovery results are split by tool so coverage stays attributable.', tags: ['ports', 'services', 'banner'] },
  { title: 'URLs & endpoints', copy: 'HTTP enumeration feeds observations that become evidence.', tags: ['HTTP', 'paths', 'methods'] },
];

const WORLD_MONITOR = [
  { label: 'Register', copy: 'Add observed deployments as authorized World Monitor targets.' },
  { label: 'Reachability', copy: 'Check live connectivity of each registered deployment.' },
  { label: 'Inventory', copy: 'Discovery produces real, enumerated inventory entries.' },
  { label: 'Drive assessments', copy: 'Use World Monitor inventory as a first-class assessment source.' },
];

const EVIDENCE_CHAIN = [
  { label: 'Observation', copy: 'What a tool actually returned to CyberAgent.\nNo interpretation yet.' },
  { label: 'Evidence', copy: 'A persisted, immutable record with source, scope and tool identity.' },
  { label: 'Validation', copy: 'Deterministic rules confirm the record is in scope and well-formed.' },
  { label: 'Verified finding', copy: 'A finding is only published when evidence validates.' },
  { label: 'Report', copy: 'Traceable from assessment through evidence to the published report.' },
];

const REPORT_TRACE = [
  'Assessment → observations',
  'Observations → evidence',
  'Evidence → validated findings',
  'Findings → report',
];

const TOOL_IDS = ['subfinder', 'assetfinder', 'dnsx', 'nmap', 'httpx', 'gau', 'whatweb', 'nuclei'];

const hopRow = (hops: string[]) => (
  <div className="mt-4 flex flex-wrap items-center gap-x-2 gap-y-1.5">
    {hops.map((n, i, arr) => (
      <React.Fragment key={n}>
        <span className="mono-cell rounded-full border border-line px-2.5 py-1 text-[9px] uppercase tracking-[0.1em] text-muted">
          {n}
        </span>
        {i < arr.length - 1 && <ArrowRight className="h-3 w-3 shrink-0 text-accent/60" strokeWidth={1.5} aria-hidden="true" />}
      </React.Fragment>
    ))}
  </div>
);

const MARQUEE_TERMS = ['Discovery', 'Enumeration', 'Observations', 'Evidence', 'Validation', 'Finding', 'Report'];

const CHAIN_GATES: Array<{ label: string; copy: string; icon: LucideIcon }> = [
  { label: 'Observation', copy: 'What a tool returned, persisted verbatim.', icon: ScanLine },
  { label: 'Evidence', copy: 'Immutable record — source, scope, tool identity.', icon: Boxes },
  { label: 'Validation', copy: 'Deterministic rules confirm scope + form.', icon: Eye },
  { label: 'Verified finding', copy: 'Published only when evidence validates.', icon: ShieldCheck },
];

const TRACE_STEPS = ['Assessment', 'Observations', 'Evidence', 'Findings', 'Report'];

const Magnetic: React.FC<{ children: React.ReactNode; strength?: number; className?: string }> = ({
  children,
  strength = 0.18,
  className,
}) => {
  const reduce = useReducedMotion();
  const mx = useMotionValue(0);
  const my = useMotionValue(0);
  const x = useSpring(mx, { stiffness: 260, damping: 20 });
  const y = useSpring(my, { stiffness: 260, damping: 20 });

  return (
    <motion.div
      className={className}
      style={reduce ? undefined : { x, y }}
      onMouseMove={(e) => {
        if (reduce) return;
        const rect = e.currentTarget.getBoundingClientRect();
        mx.set((e.clientX - rect.left - rect.width / 2) * strength);
        my.set((e.clientY - rect.top - rect.height / 2) * strength);
      }}
      onMouseLeave={() => {
        mx.set(0);
        my.set(0);
      }}
    >
      {children}
    </motion.div>
  );
};

const TiltPanel: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => {
  const reduce = useReducedMotion();
  const rx = useMotionValue(0);
  const ry = useMotionValue(0);
  const srx = useSpring(rx, { stiffness: 140, damping: 16 });
  const sry = useSpring(ry, { stiffness: 140, damping: 16 });

  return (
    <motion.div
      className={className}
      style={reduce ? undefined : { rotateX: srx, rotateY: sry, transformPerspective: 1100 }}
      onMouseMove={(e) => {
        if (reduce) return;
        const rect = e.currentTarget.getBoundingClientRect();
        const px = (e.clientX - rect.left) / rect.width - 0.5;
        const py = (e.clientY - rect.top) / rect.height - 0.5;
        rx.set(-py * 4);
        ry.set(px * 5);
      }}
      onMouseLeave={() => {
        rx.set(0);
        ry.set(0);
      }}
    >
      {children}
    </motion.div>
  );
};

const RadarBackdrop: React.FC = () => {
  const reduce = useReducedMotion();
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
      <div className="tile-grid absolute inset-0" />
      <div className="absolute left-1/2 top-1/2 h-[520px] w-[520px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-line/70" />
      <div className="absolute left-1/2 top-1/2 h-[360px] w-[360px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-line/60" />
      <div className="absolute left-1/2 top-1/2 h-[200px] w-[200px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-line/50" />
      {!reduce && (
        <div className="absolute left-1/2 top-1/2 h-[520px] w-[520px] -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-full">
          <div className="radar-sweep h-full w-full" />
        </div>
      )}
      <div className="absolute -top-24 right-[6%] h-[460px] w-[460px] rounded-full bg-accent/[0.07] blur-[120px]" />
      <div className="absolute bottom-[-12%] left-[10%] h-[360px] w-[360px] rounded-full bg-accent/[0.04] blur-[120px]" />
    </div>
  );
};

const SweepX: React.FC = () => {
  const reduce = useReducedMotion();
  if (reduce) return null;
  return (
    <motion.div
      className="pointer-events-none absolute inset-y-0 left-0 w-1/3 overflow-hidden"
      style={{ x: '-100%' }}
      animate={{ x: '200%' }}
      transition={{ duration: 5.2, ease: 'linear', repeat: Infinity, repeatDelay: 1.5 }}
      aria-hidden="true"
    >
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-accent/[0.06] to-transparent" />
      <div className="absolute inset-y-0 right-0 w-px bg-accent/40" />
    </motion.div>
  );
};

const SweepY: React.FC = () => {
  const reduce = useReducedMotion();
  if (reduce) return null;
  return (
    <motion.div
      className="pointer-events-none absolute inset-x-0 top-0 h-1/3 overflow-hidden"
      style={{ y: '-100%' }}
      animate={{ y: '200%' }}
      transition={{ duration: 4.6, ease: 'linear', repeat: Infinity, repeatDelay: 1.2 }}
      aria-hidden="true"
    >
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-accent/[0.06] to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-px bg-accent/40" />
    </motion.div>
  );
};

const MarqueeStrip: React.FC = () => {
  const reduce = useReducedMotion();

  if (reduce) {
    return (
      <div className="flex flex-wrap items-center justify-center gap-x-2 gap-y-2 border-b border-line bg-bg px-5 py-3">
        {MARQUEE_TERMS.map((t, i, arr) => (
          <span key={t} className="flex items-center gap-2 whitespace-nowrap text-[10px] font-medium uppercase tracking-[0.14em] text-faint">
            {t}
            {i < arr.length - 1 && <ArrowRight className="h-2.5 w-2.5 text-accent/50" strokeWidth={1.5} aria-hidden="true" />}
          </span>
        ))}
      </div>
    );
  }

  return (
    <div className="marquee-mask overflow-hidden border-b border-line bg-bg py-3" aria-hidden="true">
      <div className="ca-marquee flex w-max">
        {[0, 1].map((copy) => (
          <div key={copy} className="flex shrink-0 items-center gap-8 pr-8">
            {MARQUEE_TERMS.map((t) => (
              <span key={t} className="flex items-center gap-8 whitespace-nowrap text-[10px] font-medium uppercase tracking-[0.14em] text-faint">
                {t}
                <ArrowRight className="h-2.5 w-2.5 text-accent/50" strokeWidth={1.5} aria-hidden="true" />
              </span>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
};

const HopFlow: React.FC = () => {
  const reduce = useReducedMotion();
  const [active, setActive] = useState(0);

  useEffect(() => {
    if (reduce) return;
    const id = window.setInterval(() => setActive((a) => (a + 1) % HERO_HOPS.length), 2000);
    return () => window.clearInterval(id);
  }, [reduce]);

  const [stageLabel, stageSub] = HERO_HOPS[active];

  return (
    <div className="relative">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <span className="mono-cell text-[10px] uppercase tracking-[0.14em] text-faint">assessment pipeline</span>
        <span className="flex items-center gap-1.5 text-[10px] text-faint">
          <span className="dot dot-ok" aria-hidden="true" /> conceptual
        </span>
      </div>

      <div className="relative flex min-h-[96px] items-center gap-2 overflow-hidden px-1.5 py-3">
        {!reduce && <SweepX />}
        <div className="flex flex-wrap items-stretch gap-y-1">
          {HERO_HOPS.map(([label, sub], i) => {
            const state = reduce ? 'idle' : i === active ? 'active' : i < active ? 'done' : 'idle';
            return (
              <React.Fragment key={label}>
                <div
                  className={`flex min-w-[96px] flex-1 flex-col gap-1 rounded-xl px-2.5 py-2 transition-colors duration-500 ease-spring ${
                    state === 'active'
                      ? 'bg-surface-2 ring-1 ring-accent/30'
                      : state === 'done'
                        ? 'bg-surface-2/60'
                        : 'hover:bg-surface-2'
                  }`}
                >
                  <span className={`text-[10.5px] font-semibold transition-colors duration-500 ${state === 'active' ? 'text-accent' : 'text-text'}`}>
                    {label}
                  </span>
                  <span className="mono-cell text-[8.5px] uppercase tracking-[0.12em] text-faint">{sub}</span>
                </div>
                {i < HERO_HOPS.length - 1 && (
                  <span className="my-auto shrink-0">
                    <ArrowRight
                      className={`h-3 w-3 transition-colors duration-500 ${i < active ? 'text-accent/80' : 'text-accent/35'}`}
                      strokeWidth={1.5}
                      aria-hidden="true"
                    />
                  </span>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          <AnimatePresence mode="wait">
            <motion.span
              key={reduce ? 'static' : active}
              initial={reduce ? false : { opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={reduce ? undefined : { opacity: 0, y: -6 }}
              transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
              className="text-[11px] font-semibold text-text"
            >
              stage: {stageLabel}
            </motion.span>
          </AnimatePresence>
          <span className="mono-cell truncate text-[8.5px] uppercase tracking-[0.14em] text-faint">{stageSub}</span>
        </div>
        <div className="flex items-center gap-1" aria-label="Pipeline stage">
          {HERO_HOPS.map(([label], i) => (
            <button
              key={label}
              type="button"
              onClick={() => setActive(i)}
              aria-label={`Activate stage ${label}`}
              aria-current={i === active}
              className={`h-1.5 rounded-full transition-colors duration-500 ease-spring ${i === active ? 'w-4 bg-accent' : 'w-1.5 bg-line-strong hover:bg-accent/50'}`}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

const StageGrid: React.FC = () => {
  const reduce = useReducedMotion();
  return (
    <div className="grid flex-1 grid-cols-3 content-center gap-2" role="list" aria-label="Assessment pipeline stages">
      {PIPELINE.map((step, i) => {
        const Icon = step.icon;
        return (
          <div
            key={step.label}
            role="listitem"
            className={`flex min-h-[76px] flex-col justify-between rounded-xl border p-2.5 transition-colors duration-500 ease-spring ${
              i % 3 === 1 ? 'border-accent/20 bg-accent/[0.03]' : 'border-line bg-surface-2/60'
            } hover:border-accent/40`}
          >
            <div className="flex items-start justify-between">
              <Icon className="h-3.5 w-3.5 text-accent/80" strokeWidth={1.5} aria-hidden="true" />
              <span className="mono-cell text-[8px] text-faint">0{i + 1}</span>
            </div>
            <div>
              <span className="block text-[11px] font-semibold leading-tight text-text">{step.label}</span>
              {!reduce && <span className="mt-0.5 block text-[8.5px] text-faint">{step.sub}</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
};

const ChainGates: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const inView = useInView(ref, { once: true, margin: '-20% 0px' });
  const lit = reduce || inView;

  return (
    <div ref={ref} className="flex flex-1 flex-col justify-center gap-2.5">
      {CHAIN_GATES.map((g, i) => {
        const Icon = g.icon;
        return (
          <div key={g.label} className="flex items-center gap-3">
            <span
              className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border transition-colors duration-500 ease-spring ${
                lit ? 'border-accent/40 bg-accent/[0.06] text-accent' : 'border-line bg-surface-2 text-faint'
              }`}
            >
              <Icon className="h-3.5 w-3.5" strokeWidth={1.5} aria-hidden="true" />
            </span>
            <div className="min-w-0 flex-1">
              <span className={lit ? 'text-[11.5px] font-semibold text-text' : 'text-[11.5px] font-semibold text-muted'}>{g.label}</span>
              <span className="block overflow-hidden text-ellipsis whitespace-nowrap text-[10px] leading-tight text-faint">{g.copy}</span>
            </div>
            {i < CHAIN_GATES.length - 1 && <ArrowRight className="h-3 w-3 shrink-0 text-accent/40" strokeWidth={1.5} aria-hidden="true" />}
          </div>
        );
      })}
    </div>
  );
};

const TraceBar: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const inView = useInView(ref, { once: true, margin: '-20% 0px' });

  return (
    <div ref={ref} className="flex flex-1 flex-col justify-center">
      <div className="relative overflow-hidden rounded-xl border border-line bg-surface-2 p-3">
        {!reduce && inView && (
          <motion.div
            className="absolute inset-x-0 bottom-0 h-px bg-accent"
            initial={{ scaleX: 0 }}
            animate={{ scaleX: 1 }}
            transition={{ duration: 1.3, ease: 'easeOut', delay: 0.2 }}
            style={{ transformOrigin: 'left' }}
            aria-hidden="true"
          />
        )}
        <div className="flex flex-wrap items-center gap-x-2 gap-y-2">
          {TRACE_STEPS.map((t, i, arr) => (
            <React.Fragment key={t}>
              <span
                className={`rounded-full px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.12em] ${
                  i === arr.length - 1
                    ? 'border border-accent/30 bg-accent/[0.06] text-accent'
                    : 'border border-line bg-bg text-muted'
                }`}
              >
                {t}
              </span>
              {i < arr.length - 1 && <ArrowRight className="h-3 w-3 text-accent/40" strokeWidth={1.5} aria-hidden="true" />}
            </React.Fragment>
          ))}
          <span className="flex items-center gap-1.5 text-[10px] text-faint">
            <Fingerprint className="h-3 w-3 text-accent" strokeWidth={1.5} aria-hidden="true" />
            artifact fingerprint
          </span>
        </div>
      </div>
      <p className="mt-3 text-[11px] leading-relaxed text-muted">
        No observation, no evidence, no finding, no report — and every artifact carries a fingerprint.
      </p>
    </div>
  );
};

const OrbitMark: React.FC = () => {
  const reduce = useReducedMotion();
  return (
    <div className="flex flex-1 flex-col">
      <div className="relative mx-auto flex h-24 w-24 items-center justify-center" aria-hidden="true">
        <div className="absolute inset-0 rounded-full border border-line" />
        {!reduce && (
          <motion.div
            className="absolute inset-0 rounded-full border border-dashed border-accent/25"
            animate={{ rotate: 360 }}
            transition={{ duration: 40, ease: 'linear', repeat: Infinity }}
          />
        )}
        <div className="relative flex h-9 w-9 items-center justify-center rounded-full border border-accent/40 bg-accent/[0.06]">
          <Globe className="h-4 w-4 text-accent" strokeWidth={1.5} aria-hidden="true" />
        </div>
        {!reduce && (
          <motion.div
            className="absolute inset-0"
            animate={{ rotate: 360 }}
            transition={{ duration: 40, ease: 'linear', repeat: Infinity }}
          >
            <span className="absolute left-1/2 top-0 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent shadow-[0_0_12px_3px_rgba(232,255,61,0.4)]" />
          </motion.div>
        )}
      </div>
      <div className="mt-4 grid grid-cols-2 gap-1.5">
        {WORLD_MONITOR.map((w) => (
          <span
            key={w.label}
            className="mono-cell rounded-md border border-line bg-surface-2 px-2 py-1.5 text-[9px] uppercase tracking-[0.08em] text-muted"
          >
            {w.label}
          </span>
        ))}
      </div>
      <p className="mt-3 text-[11px] leading-relaxed text-muted">
        Registered deployments are reachability-checked and usable as authorized assessment sources.
      </p>
    </div>
  );
};

const Landing: React.FC = () => {
  const navigate = useNavigate();
  const reduce = useReducedMotion();

  return (
    <div className="min-h-dvh bg-bg text-text">
      {/* ==================== RESIZABLE NAVBAR (single primary nav) ==================== */}
      <ResizableNavbarDemo />

      <a href="#landing-main" className="skip-link">Skip to content</a>

      <main id="landing-main" className="pt-[72px] md:pt-[84px]">
        {/* ==================== HERO ==================== */}
        <section className="relative overflow-hidden pt-24 md:pt-32">
          <RadarBackdrop />

          <div className="relative mx-auto max-w-[1440px] px-5 pb-16 pt-10 md:px-8 md:pb-24 md:pt-14">
            <Reveal>
              <p className="eyebrow mb-5">Authorized security assessment</p>
            </Reveal>
            <Reveal delay={0.06}>
              <h1 className="max-w-[18ch] text-[clamp(2.4rem,7vw,5.6rem)] font-semibold leading-[1.02] tracking-[-0.035em] text-text">
                Security assessment
                <span className="block text-accent">without blind spots.</span>
              </h1>
            </Reveal>
            <Reveal delay={0.12}>
              <p className="mt-6 max-w-[52ch] text-[clamp(0.9rem,1.6vw,1.05rem)] leading-relaxed text-muted">
                Assess what you expose. Trace what you observe. Report what you can prove.
                CyberAgent runs authorized, scope-gated assessments and turns real
                observations into evidence-backed findings — never invented intelligence.
              </p>
            </Reveal>
            <Reveal delay={0.18}>
              <div className="mt-9 flex flex-wrap items-center gap-3">
                <Magnetic>
                  <Button variant="primary" onClick={() => navigate('/auth?mode=signup')}>
                    Get started
                    <ArrowRight className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
                  </Button>
                </Magnetic>
                <Link to="/#flow" className="no-underline">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-4 py-2 text-[12px] font-medium text-muted transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text">
                    See how it works
                    <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
                  </span>
                </Link>
              </div>
            </Reveal>

            {/* Conceptual hop panel — editorial visualization, not live telemetry */}
            <Reveal delay={0.24} className="mt-14">
              <TiltPanel className="max-w-[900px]">
                <div className="panel-2 relative overflow-hidden">
                  <HopFlow />
                </div>
              </TiltPanel>
            </Reveal>
          </div>

          <MarqueeStrip />
        </section>

        {/* ==================== SCROLL-LINKED PIPELINE ==================== */}
        <section id="flow" className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
          <div className="grid grid-cols-1 gap-10 lg:grid-cols-12 lg:gap-8">
            <div className="lg:col-span-4">
              <div className="lg:sticky lg:top-36">
                <Reveal>
                  <p className="eyebrow mb-4">Product flow</p>
                </Reveal>
                <Reveal delay={0.05}>
                  <h2 className="mb-5 max-w-[24ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
                    Every finding you report is traceable to a declared source.
                  </h2>
                </Reveal>
                <Reveal delay={0.1}>
                  <p className="mb-8 max-w-[44ch] text-[12.5px] leading-relaxed text-muted">
                    The pipeline is a single, staged path. Each step consumes the previous stage's
                    persisted output, so an inspection is never more than one hop from its evidence.
                  </p>
                </Reveal>
                <Reveal delay={0.15}>
                  <div className="panel-2 flex items-center gap-2.5 px-4 py-3">
                    <span className={reduce ? 'dot dot-ok' : 'dot dot-active'} aria-hidden="true" />
                    <span className="mono-cell text-[9.5px] uppercase tracking-[0.14em] text-faint">
                      scroll to trace the pipeline
                    </span>
                  </div>
                </Reveal>
              </div>
            </div>
            <PipelineTrack reduce={reduce} />
          </div>
        </section>

        {/* ==================== CAPABILITY BENTO ==================== */}
        <section id="capabilities" className="border-t border-line bg-bg-2">
          <div className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
            <Reveal>
              <p className="eyebrow mb-4">Capability matrix</p>
              <h2 className="max-w-[26ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
                One workstation, from intake to export.
              </h2>
            </Reveal>

            <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-12">
              {/* Honesty strip */}
              <Reveal className="h-full md:col-span-2 lg:col-span-12">
                <div className="flex h-full flex-wrap items-center justify-between gap-4 rounded-2xl border border-line bg-surface px-5 py-4">
                  <span className="text-[12.5px] font-semibold text-text">Honest by construction.</span>
                  <div className="flex flex-wrap gap-1.5">
                    {['no fabricated telemetry', 'scope-gated', 'deterministic validation'].map((t) => (
                      <span
                        key={t}
                        className="mono-cell rounded-full border border-accent/25 bg-accent/[0.04] px-2.5 py-1 text-[9px] uppercase tracking-[0.1em] text-accent"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              </Reveal>

              {/* Assessment pipeline — stage grid */}
              <Reveal className="h-full md:col-span-2 lg:col-span-7">
                <div className="tile-grid flex h-full flex-col overflow-hidden rounded-2xl border border-line bg-surface p-5">
                  <div className="mb-3 flex items-center justify-between">
                    <h3 className="text-[12.5px] font-semibold text-text">Assessment pipeline</h3>
                    <span className="mono-cell text-[9px] uppercase tracking-[0.14em] text-faint">9 stages</span>
                  </div>
                  <StageGrid />
                </div>
              </Reveal>

              {/* Tool coverage */}
              <Reveal className="h-full md:col-span-1 lg:col-span-5">
                <div className="flex h-full flex-col rounded-2xl border border-line bg-surface p-5">
                  <h3 className="mb-3 text-[12.5px] font-semibold text-text">Tool coverage</h3>
                  <div className="grid flex-1 grid-cols-2 content-start gap-2">
                    {TOOL_IDS.map((id, i) => (
                      <span key={id} className="flex items-center gap-2 rounded-lg border border-line bg-surface-2 px-3 py-2 text-[11px] text-text">
                        <span className={`h-1 w-1 shrink-0 rounded-full ${i % 3 === 0 ? 'bg-accent' : 'bg-line-strong'}`} aria-hidden="true" />
                        {id}
                      </span>
                    ))}
                  </div>
                  <p className="mt-3 text-[11px] leading-relaxed text-muted">
                    The scanner inventory is probed on the host. A missing binary is a recorded gap — never a simulated result.
                  </p>
                </div>
              </Reveal>

              {/* Attack surface */}
              <Reveal className="h-full md:col-span-1 lg:col-span-5">
                <div className="relative flex h-full flex-col overflow-hidden rounded-2xl border border-line bg-surface p-5">
                  <SweepY />
                  <h3 className="mb-1.5 text-[12.5px] font-semibold text-text">Attack surface</h3>
                  <p className="flex-1 text-[11.5px] leading-relaxed text-muted">
                    Domains, subdomains, IPs, ports, services, technologies — inventoried only from real, attributed tool output.
                  </p>
                  {hopRow(['Domains', 'IPs & ports', 'Services', 'Technologies'])}
                </div>
              </Reveal>

              {/* Evidence first */}
              <Reveal className="h-full md:col-span-1 lg:col-span-7">
                <div className="flex h-full flex-col rounded-2xl border border-line bg-surface p-5">
                  <h3 className="mb-4 text-[12.5px] font-semibold text-text">Evidence first</h3>
                  <ChainGates />
                </div>
              </Reveal>

              {/* World Monitor */}
              <Reveal className="h-full md:col-span-1 lg:col-span-4">
                <div className="flex h-full flex-col rounded-2xl border border-line bg-surface p-5">
                  <h3 className="mb-3 text-[12.5px] font-semibold text-text">World Monitor</h3>
                  <OrbitMark />
                </div>
              </Reveal>

              {/* Report traceability */}
              <Reveal className="h-full md:col-span-2 lg:col-span-8">
                <div className="flex h-full flex-col rounded-2xl border border-line bg-surface p-5">
                  <h3 className="mb-4 text-[12.5px] font-semibold text-text">Report traceability</h3>
                  <TraceBar />
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ==================== ATTACK SURFACE ==================== */}
        <section id="surface" className="border-y border-line bg-bg">
          <div className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
            <Reveal>
              <p className="eyebrow mb-4">Attack surface</p>
              <h2 className="mb-4 max-w-[26ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
                Inventory everything you expose.
              </h2>
              <p className="mb-10 max-w-[56ch] text-[12.5px] leading-relaxed text-muted">
                CyberAgent inventories authorized scope from real tool output. If a service
                is listening, it becomes observable. If it is observed, it can become evidence.
              </p>
            </Reveal>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {SURFACE.map((card, i) => (
                <Reveal key={card.title} delay={0.05 * i}>
                  <div className="flex h-full flex-col rounded-2xl border border-line bg-surface-2 p-5">
                    <h3 className="text-[13.5px] font-semibold text-text">{card.title}</h3>
                    <p className="mt-1.5 flex-1 text-[11.5px] leading-relaxed text-muted">{card.copy}</p>
                    <div className="mt-4 flex flex-wrap gap-1.5">
                      {card.tags.map((t) => (
                        <span key={t} className="mono-cell rounded-full border border-line px-2.5 py-1 text-[9px] uppercase tracking-[0.1em] text-faint">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        {/* ==================== WORLD MONITOR ==================== */}
        <section id="monitor" className="border-t border-line bg-bg-2">
          <div className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
            <Reveal>
              <p className="eyebrow mb-4 flex items-center gap-2">
                <Globe className="h-3.5 w-3.5 text-accent" strokeWidth={1.5} aria-hidden="true" />
                World Monitor
              </p>
              <h2 className="mb-12 max-w-[24ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
                The operational picture is also an assessment source.
              </h2>
            </Reveal>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
              {WORLD_MONITOR.map((w, i) => (
                <Reveal key={w.label} delay={0.05 * i}>
                  <div className="h-full rounded-2xl border border-line bg-surface p-5">
                    <span className="mono-cell text-[9px] uppercase tracking-[0.14em] text-accent">{w.label}</span>
                    <p className="mt-2 text-[11.5px] leading-relaxed text-muted">{w.copy}</p>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        {/* ==================== EVIDENCE CHAIN ==================== */}
        <section id="evidence" className="border-t border-line bg-bg">
          <div className="mx-auto max-w-[1440px] px-5 py-16 md:px-8 md:py-24">
            <Reveal>
              <p className="eyebrow mb-4">Evidence chain</p>
              <h2 className="mb-12 max-w-[26ch] text-[clamp(1.6rem,3.4vw,2.6rem)] font-semibold tracking-[-0.025em]">
                Observation before evidence. Evidence before findings.
              </h2>
            </Reveal>
            <div className="space-y-4">
              {EVIDENCE_CHAIN.map((n, i) => (
                <Reveal key={n.label} delay={0.04 * i}>
                  <div className="flex items-start gap-4 rounded-2xl border border-line bg-surface p-5">
                    <span className="mono-cell mt-0.5 text-[10px] text-accent">0{i + 1}</span>
                    <div className="min-w-0 flex-1">
                      <h3 className="text-[13.5px] font-semibold text-text">{n.label}</h3>
                      <p className="mt-0.5 whitespace-pre-line text-[11.5px] leading-relaxed text-muted">{n.copy}</p>
                    </div>
                    {i < EVIDENCE_CHAIN.length - 1 && (
                      <ArrowRight className="mt-1 h-4 w-4 shrink-0 text-accent/50" strokeWidth={1.5} aria-hidden="true" />
                    )}
                  </div>
                </Reveal>
              ))}
            </div>
            <Reveal delay={0.1}>
              <div className="mt-8 rounded-2xl border border-line bg-surface-2 p-5">
                <p className="eyebrow mb-3">Report traceability</p>
                <div className="flex flex-col gap-2">
                  {REPORT_TRACE.map((r) => (
                    <span key={r} className="mono-cell text-[11px] text-muted">{r}</span>
                  ))}
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ==================== CTA ==================== */}
        <section className="border-t border-line">
          <div className="mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-6 px-5 py-16 md:flex-row md:items-center md:px-8 md:py-24">
            <Reveal>
              <h2 className="max-w-[20ch] text-[clamp(1.7rem,3.6vw,2.8rem)] font-semibold tracking-[-0.03em]">
                Start assessing what you expose.
              </h2>
            </Reveal>
            <Reveal delay={0.08}>
              <div className="flex flex-wrap gap-3">
                <Button variant="primary" onClick={() => navigate('/auth?mode=signup')}>
                  Get started
                  <ArrowRight className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
                </Button>
                <Button variant="outline" onClick={() => navigate('/auth')}>
                  Sign in
                </Button>
              </div>
            </Reveal>
          </div>
        </section>
      </main>

      {/* ==================== FOOTER ==================== */}
      <footer className="border-t border-line px-5 py-10 md:px-8">
        <div className="mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
          <div className="flex items-center gap-2.5">
            <Radar className="h-4 w-4 text-accent" strokeWidth={1.5} aria-hidden="true" />
            <span className="text-[12px] font-semibold text-text">CyberAgent</span>
            <span className="eyebrow">&middot; authorized assessment</span>
          </div>
          <p className="text-[11px] text-faint">
            Assess what you expose. Trace what you observe. Report what you can prove.
          </p>
        </div>
      </footer>
    </div>
  );
};

const StepBody: React.FC<{ step: Phase }> = ({ step }) => {
  const StepIcon = step.icon;
  return (
    <div className="flex items-start gap-3">
      <span className="mt-0.5 text-accent">
        <StepIcon className="h-[18px] w-[18px]" strokeWidth={1.5} aria-hidden="true" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <h3 className="text-[13.5px] font-semibold text-text">{step.label}</h3>
          <span className="mono-cell text-[9px] uppercase tracking-[0.14em] text-faint">{step.sub}</span>
        </div>
        <p className="mt-1 text-[11.5px] leading-relaxed text-muted">{step.copy}</p>
      </div>
    </div>
  );
};

const TrackStep: React.FC<{ step: Phase; index: number; reduce: boolean | null }> = ({ step, index, reduce }) => {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-12% 0px -28% 0px' });
  const lit = reduce || inView;

  return (
    <div ref={ref} className="relative flex gap-4">
      <span
        className={`z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border font-mono text-[10px] font-semibold transition-colors duration-500 ease-spring ${
          lit ? 'border-accent/50 bg-accent text-[#0a0a08]' : 'border-line bg-bg text-faint'
        }`}
        aria-hidden="true"
      >
        {String(index + 1).padStart(2, '0')}
      </span>
      {reduce ? (
        <div className="min-w-0 flex-1 rounded-2xl border border-line bg-surface p-5">
          <StepBody step={step} />
        </div>
      ) : (
        <motion.div
          className="min-w-0 flex-1 rounded-2xl border border-line bg-surface p-5 transition-[border-color,background-color] duration-500 ease-spring"
          initial={{ opacity: 0, y: 16 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.42, ease: [0.22, 1, 0.36, 1] }}
        >
          <StepBody step={step} />
        </motion.div>
      )}
    </div>
  );
};

const PipelineTrack: React.FC<{ reduce: boolean | null }> = ({ reduce }) => {
  const trackRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: trackRef, offset: ['start 0.72', 'end 0.4'] });
  const railScale = useTransform(scrollYProgress, [0, 1], [0, 1]);

  return (
    <div ref={trackRef} className="relative lg:col-span-8">
      {!reduce && (
        <>
          <div className="absolute bottom-0 left-[15px] top-0 w-px bg-line" aria-hidden="true" />
          <motion.div
            className="absolute bottom-0 left-[15px] top-0 w-px bg-accent"
            style={{ scaleY: railScale, transformOrigin: 'top' }}
            aria-hidden="true"
          />
        </>
      )}
      <div className="space-y-3">
        {PIPELINE.map((step, i) => (
          <TrackStep key={step.label} step={step} index={i} reduce={reduce} />
        ))}
      </div>
    </div>
  );
};

export default Landing;