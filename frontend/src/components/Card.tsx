import React from 'react';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  as?: 'div' | 'section';
  className?: string;
}

/**
 * Single card foundation used by every dashboard surface.
 *
 * One radius, one border, one background, one inset highlight — every
 * component that wants a card uses this so nothing drifts visually.
 */
export const Card: React.FC<CardProps> = ({ as: Tag = 'div', className = '', children, ...rest }) => (
  <Tag
    className={`min-w-0 rounded-xl border border-line bg-surface shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] ${className}`}
    {...rest}
  >
    {children}
  </Tag>
);