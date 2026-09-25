import React, { useEffect, useRef } from 'react';
import { AlertTriangle } from 'lucide-react';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  body?: React.ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: 'default' | 'danger';
  busy?: boolean;
  backdropLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/** Modal confirmation with Escape/cancel-first focus and a busy state. */
export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  title,
  body,
  confirmLabel,
  cancelLabel = 'Cancel',
  tone = 'default',
  busy = false,
  backdropLabel,
  onConfirm,
  onCancel,
}) => {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
    };
    const prevBodyOverflow = document.body.style.overflow;
    const prevMainOverflow = document.getElementById('main')?.style.overflow;
    document.body.style.overflow = 'hidden';
    document.getElementById('main')?.style.setProperty('overflow', 'hidden');
    window.addEventListener('keydown', onKey);
    requestAnimationFrame(() => cancelRef.current?.focus());
    return () => {
      document.body.style.overflow = prevBodyOverflow;
      document.getElementById('main')?.style.setProperty('overflow', prevMainOverflow ?? '');
      window.removeEventListener('keydown', onKey);
    };
  }, [open, onCancel]);

  if (!open) return null;

  const isDanger = tone === 'danger';

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={backdropLabel ?? title}>
      <button
        type="button"
        aria-label="Dismiss"
        onClick={() => { if (!busy) onCancel(); }}
        className="overlay absolute inset-0 cursor-default"
      />
      <div className="relative z-10 w-full max-w-sm rounded-2xl border border-line bg-surface p-5 shadow-[var(--shadow-float)]">
        <div className="flex items-start gap-3">
          <span
            className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border ${
              isDanger ? 'border-critical/40 bg-critical/[0.08] text-critical' : 'border-accent/30 bg-accent/[0.06] text-accent'
            }`}
          >
            <AlertTriangle className="h-4 w-4" strokeWidth={1.5} aria-hidden="true" />
          </span>
          <div className="minw-0 flex-1">
            <h3 className="text-[13.5px] font-semibold leading-snug text-text">{title}</h3>
            {body && <div className="mt-1.5 text-[12px] leading-relaxed text-muted">{body}</div>}
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded-full border border-line px-3.5 py-1.5 text-[11.5px] text-muted transition-colors duration-500 ease-spring hover:border-line-strong hover:text-text disabled:opacity-50"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className={`rounded-full border px-3.5 py-1.5 text-[11.5px] font-medium transition-colors duration-500 ease-spring disabled:opacity-50 ${
              isDanger
                ? 'border-critical/50 bg-critical/[0.12] text-critical hover:bg-critical/20'
                : 'border-accent/50 bg-accent/10 text-accent hover:bg-accent/20'
            }`}
          >
            {busy ? 'Working…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};