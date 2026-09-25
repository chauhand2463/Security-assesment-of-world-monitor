import React, { useEffect, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  LayoutDashboard,
  Radar,
  ShieldCheck,
  ShieldAlert,
  Server,
  FileText,
  MessageSquareText,
  Cpu,
  BookOpen,
  Settings,
  LogOut,
  Menu,
  X,
  Crosshair,
  ArrowLeft,
  Globe,
  Target,
  CalendarClock,
} from 'lucide-react';
import { apiFetch } from '../api';

interface ShellProps {
  children: React.ReactNode;
  onLogout: () => void;
}

interface UserInfo {
  email?: string;
  role?: string;
}

interface ScopeInfo {
  count: number;
  sample: string[];
}

const NAV_GROUPS = [
  {
    label: 'Operations',
    items: [
      { name: 'Command Center', path: '/', icon: LayoutDashboard },
      { name: 'World Monitor', path: '/world-monitor', icon: Globe },
      { name: 'Assessments', path: '/scans', icon: ShieldCheck },
      { name: 'Findings', path: '/findings', icon: ShieldAlert },
      { name: 'Reports', path: '/reports', icon: FileText },
      { name: 'Schedules', path: '/schedules', icon: CalendarClock },
    ],
  },
  {
    label: 'Inventory',
    items: [
      { name: 'Assets', path: '/assets', icon: Server },
      { name: 'Attack Surface', path: '/surface', icon: Radar },
      { name: 'Coverage', path: '/coverage', icon: Target },
      { name: 'Tools', path: '/tools', icon: Cpu },
    ],
  },
  {
    label: 'Assistant',
    items: [
      { name: 'Assessment Assistant', path: '/chat', icon: MessageSquareText },
      { name: 'Knowledge Base', path: '/knowledge', icon: BookOpen },
    ],
  },
  {
    label: 'Workspace',
    items: [
      { name: 'Settings', path: '/settings', icon: Settings },
    ],
  },
];

export const DashboardLayout: React.FC<ShellProps> = ({ children, onLogout }) => {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [scope, setScope] = useState<ScopeInfo | null>(null);
  const [env, setEnv] = useState<{ simulation_mode: boolean } | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const reduceMotion = useReducedMotion();
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    mainRef.current?.scrollTo(0, 0);
  }, [location.pathname]);

  useEffect(() => {
    apiFetch('/auth/me')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => data && setUser({ email: data.email, role: data.role || 'user' }))
      .catch(() => {});
  }, []);

  useEffect(() => {
    apiFetch('/scans/scope')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        const list: string[] = Array.isArray(data?.scope) ? data.scope : [];
        setScope({ count: list.length, sample: list.slice(-3) });
      })
      .catch(() => {});
  }, []);

  const fetchEnv = () => {
    apiFetch('/tools/inventory')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => data && setEnv({ simulation_mode: !!data.simulation_mode }))
      .catch(() => {});
  };

  useEffect(() => {
    fetchEnv();
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  const initials = (user?.email || '?').split('@')[0].slice(0, 2).toUpperCase();

  const navBody = (
    <div className="flex flex-1 flex-col overflow-y-auto px-3 py-4">
      <NavLink
        to="/scan/new"
        className="mb-5 flex items-center justify-center gap-2 rounded-xl border border-accent/30 bg-accent/[0.08] px-3 py-2.5 text-[12.5px] font-medium text-accent transition-colors duration-500 ease-spring hover:bg-accent/[0.14]"
      >
        <Radar className="h-[17px] w-[17px]" strokeWidth={1.5} aria-hidden="true" />
        New Assessment
      </NavLink>
      <ul className="space-y-6">
        {NAV_GROUPS.map((group) => (
          <li key={group.label}>
            <p className="eyebrow px-3 pb-2.5">{group.label}</p>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <li key={item.path}>
                    <NavLink
                      to={item.path}
                      end={item.path === '/'}
                      className="group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-[12.5px] text-muted transition-colors duration-500 ease-spring hover:text-text"
                    >
                      {({ isActive }) => (
                        <>
                          {isActive && (
                            <motion.span
                              layoutId="nav-active"
                              className="absolute inset-0 rounded-xl border border-line bg-white/[0.055]"
                              transition={reduceMotion ? { duration: 0 } : { type: 'spring', stiffness: 480, damping: 34 }}
                            />
                          )}
                          <Icon
                            className={`relative z-10 h-[17px] w-[17px] shrink-0 transition-colors duration-500 ease-spring ${
                              isActive ? 'text-accent' : 'text-faint group-hover:text-text'
                            }`}
                            strokeWidth={1.5}
                            aria-hidden="true"
                          />
                          <span className={`relative z-10 min-w-0 flex-1 truncate ${isActive ? 'font-medium text-text' : ''}`}>
                            {item.name}
                          </span>
                        </>
                      )}
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        ))}
      </ul>

      <div className="mt-6 rounded-2xl border border-line bg-surface-2/70 p-3.5">
        <div className="mb-2.5 flex items-center gap-2">
          <Crosshair className="h-3.5 w-3.5 text-accent" strokeWidth={1.5} aria-hidden="true" />
          <span className="eyebrow">Authorized scope</span>
        </div>
        {scope && scope.count > 0 ? (
          <>
            <p className="mb-1.5 text-[11px] text-muted">
              {scope.count} declared target{scope.count === 1 ? '' : 's'}
            </p>
            <div className="space-y-1">
              {scope.sample.slice(-3).map((entry) => (
                <p key={entry} className="mono-cell truncate text-[10px] text-faint">
                  {entry}
                </p>
              ))}
              {scope.count > scope.sample.length && (
                <p className="mono-cell text-[10px] text-faint">+{scope.count - scope.sample.length} more</p>
              )}
            </div>
          </>
        ) : (
          <p className="text-[11px] leading-relaxed text-faint">
            No scope declared. Out-of-scope targets are rejected with 403.
          </p>
        )}
      </div>
    </div>
  );

  const pageTransition = reduceMotion ? (
    <div>{children}</div>
  ) : (
    <motion.div
      key={location.pathname}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.26, ease: [0.22, 1, 0.36, 1] }}
      style={{ willChange: 'opacity, transform' }}
    >
      {children}
    </motion.div>
  );

  return (
    <div className="flex h-[100dvh] w-full flex-col overflow-hidden text-text">
      <header className="glass z-30 mx-2 mt-2 flex h-14 shrink-0 items-center gap-3 rounded-2xl px-3 sm:mx-3 sm:mt-3 sm:px-4">
        <button
          onClick={() => setMobileOpen((v) => !v)}
          className="-ml-1 rounded-full p-2 text-muted transition-colors duration-500 ease-spring hover:bg-white/[0.05] hover:text-text lg:hidden"
          aria-label={mobileOpen ? 'Close navigation' : 'Open navigation'}
        >
          {mobileOpen ? <X className="h-5 w-5" strokeWidth={1.5} /> : <Menu className="h-5 w-5" strokeWidth={1.5} />}
        </button>

        <NavLink to="/" className="flex min-w-0 items-center gap-2.5 transition-opacity duration-500 ease-spring hover:opacity-90">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-line bg-surface-2">
            <img src="/logo.png" alt="CyberAgent" className="h-full w-full object-cover" />
          </span>
          <span className="hidden flex-col leading-none sm:flex">
            <span className="text-[15px] font-semibold tracking-tight">CyberAgent</span>
            <span className="mt-1 font-mono text-[9px] uppercase tracking-[0.2em] text-faint">Assessment Platform</span>
          </span>
        </NavLink>

        <button
          onClick={() => navigate(-1)}
          className="rounded-full p-2 text-muted transition-colors duration-500 ease-spring hover:bg-white/[0.05] hover:text-text"
          aria-label="Go back"
          title="Go back"
        >
          <ArrowLeft className="h-[17px] w-[17px]" strokeWidth={1.5} />
        </button>

        <div className="flex-1" />

        <div className="hidden items-center gap-2 rounded-full border border-line bg-white/[0.02] px-3 py-1.5 md:flex" title="Backend execution mode">
          <span className={env ? 'dot dot-ok' : 'dot dot-neutral'} />
          <span className="mono-cell text-[10px] uppercase tracking-wider text-muted">
            {env === null ? '…' : env.simulation_mode ? 'Simulation' : 'Live'}
          </span>
        </div>

        <div className="flex items-center gap-2.5 pl-1">
          <div
            className="flex h-8 w-8 items-center justify-center rounded-xl border border-line bg-surface-2 text-[11px] font-semibold text-accent"
            aria-hidden="true"
          >
            {initials}
          </div>
          <div className="hidden min-w-0 max-w-[180px] flex-col leading-tight sm:flex">
            <p className="truncate text-[11.5px] font-medium">{user?.email?.split('@')[0] || '…'}</p>
            <p className="mono-cell text-[9px] uppercase tracking-wider text-faint">{user?.role || '…'}</p>
          </div>
        </div>

        <button
          onClick={onLogout}
          className="rounded-full p-2 text-faint transition-colors duration-500 ease-spring hover:bg-critical/10 hover:text-critical"
          aria-label="Sign out"
          title="Sign out"
        >
          <LogOut className="h-[17px] w-[17px]" strokeWidth={1.5} />
        </button>
      </header>

      <div className="flex min-h-0 flex-1">
        <aside
          className="mx-3 mb-3 mt-3 hidden w-[236px] shrink-0 flex-col overflow-hidden rounded-2xl border border-line bg-surface/50 lg:flex"
          aria-label="Sidebar"
        >
          {navBody}
        </aside>

        <AnimatePresence>
          {mobileOpen && (
            <motion.div
              className="fixed inset-0 z-50 flex lg:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            >
              <div
                className="flex-1 bg-black/70 backdrop-blur-sm"
                onClick={() => setMobileOpen(false)}
                aria-hidden="true"
              />
              <motion.aside
                className="glass flex w-[272px] max-w-[82vw] flex-col overflow-hidden border-l border-line"
                initial={{ x: 40, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: 40, opacity: 0 }}
                transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
                aria-label="Sidebar"
              >
                <div className="flex h-14 items-center justify-between border-b border-line px-4">
                  <span className="text-[13px] font-semibold">Navigation</span>
                  <button
                    onClick={() => setMobileOpen(false)}
                    className="rounded-full p-1.5 text-muted transition-colors duration-500 ease-spring hover:bg-white/[0.05] hover:text-text"
                    aria-label="Close navigation"
                  >
                    <X className="h-4 w-4" strokeWidth={1.5} />
                  </button>
                </div>
                {navBody}
              </motion.aside>
            </motion.div>
          )}
        </AnimatePresence>

        <main id="main" ref={mainRef} tabIndex={-1} className="min-w-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">{pageTransition}</div>
        </main>
      </div>
    </div>
  );
};
