import React, { useCallback, useEffect, useRef } from 'react';
import { X } from 'lucide-react';

let openDrawerCount = 0;

interface DetailDrawerProps {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: string;
}

/** Right-hand detail drawer with scrim, Escape-to-close and scroll locking. */
export const DetailDrawer: React.FC<DetailDrawerProps> = ({
  open,
  title,
  onClose,
  children,
  footer,
  width = 'max-w-xl',
}) => {
  const closeRef = useRef<HTMLButtonElement>(null);

  const lock = useCallback(() => {
    openDrawerCount += 1;
    document.body.style.overflow = 'hidden';
  }, []);

  const unlock = useCallback(() => {
    openDrawerCount = Math.max(0, openDrawerCount - 1);
    if (openDrawerCount === 0) {
      document.body.style.overflow = '';
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    lock();
    return unlock;
  }, [open, lock, unlock]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    requestAnimationFrame(() => closeRef.current?.focus());
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Details">
      <button
        type="button"
        aria-label="Close drawer"
        onClick={onClose}
        className="overlay absolute inset-0 cursor-default"
      />
      <div className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-line bg-surface shadow-[var(--shadow-float)] sm:w-2/3 md:w-1/2 lg:w-[34rem] xl:w-[38rem]">
        <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-4">
          <div className="minw-0 flex-1 text-[13.5px] font-semibold text-text">{title}</div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-line text-faint transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text focus:border-accent"
          >
          <X className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
          </button>
        </div>
        <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto px-5 py-5">{children}</div>
        {footer && (
          <div className="flex flex-wrap items-center gap-2 border-t border-line px-5 py-3.5">{footer}</div>
        )}
      </div>
    </div>
  );
};