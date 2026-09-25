import React, { useCallback, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';

interface CopyButtonProps {
  value: string;
  label?: string;
  className?: string;
}

/** Copies a string to the clipboard with brief inline feedback. */
export const CopyButton: React.FC<CopyButtonProps> = ({ value, label, className }) => {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | null>(null);

  const onCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }, [value]);

  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        void onCopy();
      }}
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border border-line px-2.5 py-1 font-mono text-[10px] text-faint transition-colors duration-500 ease-spring hover:border-line-strong hover:text-muted focus:border-accent ${className ?? ''}`}
      aria-label={label ?? 'Copy to clipboard'}
      title={label ?? 'Copy to clipboard'}
    >
      {copied ? (
        <Check className="h-3 w-3 text-accent" strokeWidth={1.5} aria-hidden="true" />
      ) : (
        <Copy className="h-3 w-3" strokeWidth={1.5} aria-hidden="true" />
      )}
      {copied ? 'Copied' : label ?? 'Copy'}
    </button>
  );
};