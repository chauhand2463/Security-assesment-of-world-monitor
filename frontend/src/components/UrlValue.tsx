import React from 'react';
import { Link } from 'react-router-dom';

interface UrlValueProps {
  url: string;
  /** Internal route (e.g. `/surface?scan=1&endpoint=…`) rendered as a Link. */
  to?: string;
  className?: string;
  maxChars?: number;
}

/** URL display that wraps safely and links to an internal evidence route when given. */
export const UrlValue: React.FC<UrlValueProps> = ({ url, to, className, maxChars }) => {
  const text = maxChars && url.length > maxChars ? `${url.slice(0, maxChars)}…` : url;
  const content = <span className={`wrap-any mono-cell text-[10.5px] leading-relaxed text-text ${className ?? ''}`}>{text}</span>;

  if (!to) return content;
  return (
    <Link
      to={to}
      className="soft-link decoration-transparent hover:decoration-accent/60"
      title={url}
    >
      {content}
    </Link>
  );
};