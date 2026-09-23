import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  IconRoute,
  IconGridDots,
  IconTargetArrow,
  IconGlobe,
  IconFingerprint,
} from '@tabler/icons-react';
import {
  Navbar,
  NavBody,
  NavItems,
  DesktopNav,
  DesktopNavHeader,
  MobileNav,
  MobileNavHeader,
  MobileNavToggle,
  type NavItem,
} from './ui/resizable-navbar';

const NAV_ITEMS: NavItem[] = [
  { name: 'Pipeline', link: '#flow', icon: IconRoute },
  { name: 'Capabilities', link: '#capabilities', icon: IconGridDots },
  { name: 'Attack surface', link: '#surface', icon: IconTargetArrow },
  { name: 'World Monitor', link: '#monitor', icon: IconGlobe },
  { name: 'Evidence chain', link: '#evidence', icon: IconFingerprint },
];

const Brand: React.FC = () => (
  <Link to="/" className="flex items-center gap-2.5 no-underline" aria-label="CyberAgent home">
    <span className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-lg border border-line bg-surface-2">
      <img src="/logo.png" alt="" className="h-full w-full object-cover" />
    </span>
    <span className="flex flex-col leading-none">
      <span className="text-[13px] font-semibold tracking-tight text-text">CyberAgent</span>
      <span className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.18em] text-faint">Assessment Platform</span>
    </span>
  </Link>
);

const AuthButtons: React.FC = () => (
  <>
    <Link
      to="/auth"
      className="rounded-lg px-3 py-2 text-[12px] font-medium text-muted transition-colors duration-500 ease-spring hover:text-text"
    >
      Sign in
    </Link>
    <Link
      to="/auth?mode=signup"
      className="rounded-full border border-accent/50 bg-accent px-4 py-2 text-[12px] font-semibold text-[#0a0a08] transition-[background-color,border-color,transform] duration-500 ease-spring hover:bg-accent-bright active:scale-[0.98]"
    >
      Get started
    </Link>
  </>
);

export const ResizableNavbarDemo: React.FC = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const reduce = useReducedMotion();
  const toggleMode: 'menu' | 'close' = menuOpen ? 'close' : 'menu';
  const closeMenu = () => setMenuOpen(false);

  return (
    <Navbar>
      <NavBody menuOpen={menuOpen}>
        <DesktopNav>
          <DesktopNavHeader>
            <Brand />
          </DesktopNavHeader>
          <NavItems items={NAV_ITEMS} />
          <AuthButtons />
        </DesktopNav>

        <MobileNav>
          <MobileNavHeader>
            <Brand />
            <MobileNavToggle toggle={() => setMenuOpen((v) => !v)} toggleMode={toggleMode} menuOpen={menuOpen} />
          </MobileNavHeader>

          <AnimatePresence initial={false}>
            {menuOpen && (
              <motion.div
                key="resizable-mobile-menu"
                id="resizable-mobile-menu"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: reduce ? 0 : 0.3, ease: [0.32, 0.72, 0, 1] }}
                className="overflow-hidden"
              >
                <div className="flex flex-col gap-1 pb-1">
                  {NAV_ITEMS.map((item) => (
                    <a
                      key={item.name}
                      href={item.link}
                      onClick={closeMenu}
                      className="flex items-center gap-2.5 rounded-xl px-3 py-2.5 text-[12.5px] font-medium text-muted transition-colors duration-500 ease-spring hover:bg-white/[0.05] hover:text-text"
                    >
                      <item.icon className="h-4 w-4 text-faint" />
                      {item.name}
                    </a>
                  ))}
                  <div className="mt-1.5 flex flex-col gap-2 border-t border-line pt-3">
                    <Link
                      to="/auth"
                      onClick={closeMenu}
                      className="flex w-full items-center justify-center rounded-full border border-line bg-white/[0.015] px-4 py-2 text-[12.5px] font-medium text-muted transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text"
                    >
                      Sign in
                    </Link>
                    <Link
                      to="/auth?mode=signup"
                      onClick={closeMenu}
                      className="flex w-full items-center justify-center rounded-full border border-accent/50 bg-accent px-4 py-2 text-[12.5px] font-semibold text-[#0a0a08] transition-[background-color,border-color,transform] duration-500 ease-spring hover:bg-accent-bright active:scale-[0.98]"
                    >
                      Get started
                    </Link>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </MobileNav>
      </NavBody>
    </Navbar>
  );
};