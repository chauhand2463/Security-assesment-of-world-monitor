import React from 'react';
import { Card } from '../Card';
import { SectionHeader } from '../SectionHeader';

interface ChartCardProps {
  title: string;
  icon?: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
  note?: React.ReactNode;
}

/**
 * Standard chart surface: aligned header row plus a vertically flexible
 * content area. Used for every analytics card so charts share one grid.
 */
export const ChartCard: React.FC<ChartCardProps> = ({ title, icon, meta, actions, className = '', children, note }) => (
  <Card className={`flex h-full flex-col ${className}`}>
    <SectionHeader title={title} icon={icon} meta={meta} actions={actions} className="px-5 pt-5 pb-4" />
    <div className="flex flex-1 flex-col px-5 pb-5">
      {children}
      {note && <p className="mt-auto pt-3 text-[10px] leading-relaxed text-faint">{note}</p>}
    </div>
  </Card>
);