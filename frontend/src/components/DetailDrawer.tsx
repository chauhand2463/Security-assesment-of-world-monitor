import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';

interface DetailDrawerProps {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: string;
}

/** Right-hand detail drawer with scrim, Escape-to-close, portal isolation, and smooth independent scrolling. */
export const DetailDrawer: React.FC<DetailDrawerProps> = ({
  open,
  title,
  onClose,
  children,
  footer,
  width,
}) => {
  const [mounted, setMounted] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!open) return;
    const mainEl = document.getElementById('main');
    const prevBodyOverflow = document.body.style.overflow;
    const prevMainOverflow = mainEl?.style.overflow ?? '';

    document.body.style.overflow = 'hidden';
    if (mainEl) {
      mainEl.style.overflow = 'hidden';
    }

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    requestAnimationFrame(() => closeRef.current?.focus());

    return () => {
      document.body.style.overflow = prevBodyOverflow;
      if (mainEl) {
        mainEl.style.overflow = prevMainOverflow;
      }
      window.removeEventListener('keydown', onKey);
    };
  }, [open, onClose]);

  if (!mounted) return null;

  return createPortal(
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label="Details">
          {/* Backdrop scrim */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/65 backdrop-blur-sm cursor-default"
            aria-hidden="true"
          />

          {/* Drawer slide-over */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 30, stiffness: 360 }}
            className={`relative z-10 flex h-full w-full flex-col border-l border-line bg-surface shadow-[var(--shadow-float)] sm:w-2/3 md:w-1/2 lg:w-[36rem] xl:w-[42rem] ${
              width || ''
            }`}
          >
            {/* Drawer Header (Fixed top) */}
            <div className="flex shrink-0 items-center justify-between gap-3 border-b border-line bg-surface/95 px-6 py-4 backdrop-blur-md">
              <div className="min-w-0 flex-1 text-[13.5px] font-semibold text-text">{title}</div>
              <button
                ref={closeRef}
                type="button"
                onClick={onClose}
                aria-label="Close drawer"
                className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-line text-muted transition-colors duration-300 hover:border-line-strong hover:bg-white/[0.05] hover:text-text focus-visible:border-accent"
              >
                <X className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
              </button>
            </div>

            {/* Drawer Body (Scrollable with custom scrollbar) */}
            <div className="scrollbar-thin overscroll-contain min-h-0 flex-1 overflow-y-auto px-6 py-5">
              {children}
            </div>

            {/* Drawer Footer (Fixed bottom) */}
            {footer && (
              <div className="shrink-0 flex flex-wrap items-center justify-between gap-2 border-t border-line bg-surface-2/70 px-6 py-3.5 backdrop-blur-md">
                {footer}
              </div>
            )}
          </motion.div>
        </div>
      )}
    </AnimatePresence>,
    document.body
  );
};