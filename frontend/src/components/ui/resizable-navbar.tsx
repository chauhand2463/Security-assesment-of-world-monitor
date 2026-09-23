import React, { useEffect, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { IconMenu2, IconX } from '@tabler/icons-react';
import { cn } from '../../lib/utils';

export interface NavItem {
  name: string;
  link: string;
  icon: React.ComponentType<{ className?: string }>;
}

/* Fixed outer shell that settles the pill into place on mount. */
export const Navbar: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const reduce = useReducedMotion();
  return (
    <motion.nav
      initial={reduce ? false : { y: -16, opacity: 0 }}
      animate={reduce ? undefined : { y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: [0.32, 0.72, 0, 1] }}
      className="fixed inset-x-0 top-0 z-[60] flex justify-center px-3 pt-2"
      aria-label="Primary navigation"
    >
      {children}
    </motion.nav>
  );
};

/* The resizable pill. Shrinks to a dense glassy capsule once scrolled. */
export const NavBody: React.FC<{ children: React.ReactNode; menuOpen?: boolean; className?: string }> = ({
  children,
  menuOpen = false,
  className,
}) => {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <div
      className={cn(
        'relative flex w-full items-center justify-between gap-3 rounded-full border transition-all duration-300 ease-out',
        menuOpen
          ? 'h-auto flex-col items-stretch rounded-[1.75rem] px-3 py-2'
          : scrolled
            ? 'h-12 flex-row px-4 md:h-14'
            : 'h-14 flex-row px-4 md:h-16',
        menuOpen ? 'w-full' : 'w-full lg:w-fit',
        scrolled ? 'glass shadow-lift' : 'border-line bg-surface/70',
        className
      )}
    >
      {children}
    </div>
  );
};

export const NavItems: React.FC<{ items: NavItem[]; className?: string }> = ({ items, className }) => (
  <div className={cn('flex items-center gap-5 lg:gap-6', className)}>
    {items.map((item) => (
      <a
        key={item.name}
        href={item.link}
        className="flex items-center gap-1.5 whitespace-nowrap text-[12px] font-medium text-muted transition-colors duration-500 ease-spring hover:text-text"
      >
        <item.icon className="h-3.5 w-3.5 text-faint" />
        <span>{item.name}</span>
      </a>
    ))}
  </div>
);

export const DesktopNav: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <div className={cn('hidden items-center gap-5 lg:flex lg:gap-8', className)}>{children}</div>
);

export const DesktopNavHeader: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="flex items-center gap-2.5">{children}</div>
);

export const MobileNav: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="relative w-full lg:hidden">{children}</div>
);

export const MobileNavHeader: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="flex w-full items-center justify-between gap-3">{children}</div>
);

export const MobileNavToggle: React.FC<{
  toggle: () => void;
  toggleMode: 'menu' | 'close';
  menuOpen: boolean;
}> = ({ toggle, toggleMode, menuOpen }) => (
  <button
    type="button"
    onClick={toggle}
    aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
    aria-expanded={menuOpen}
    aria-controls="resizable-mobile-menu"
    className="-mr-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-line bg-surface-2 text-muted transition-colors duration-500 ease-spring hover:text-text"
  >
    <AnimatePresence mode="wait" initial={false}>
      <motion.span
        key={toggleMode}
        initial={{ y: -12, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: 12, opacity: 0 }}
        transition={{ duration: 0.18, ease: [0.32, 0.72, 0, 1] }}
        className="flex"
      >
        {toggleMode === 'menu' ? (
          <IconMenu2 className="h-4 w-4" stroke={1.5} />
        ) : (
          <IconX className="h-4 w-4" stroke={1.5} />
        )}
      </motion.span>
    </AnimatePresence>
  </button>
);