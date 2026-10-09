import React from 'react';
import { LucideIcon, BarChart3 } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface ChartCardProps {
  title: string;
  subtitle?: string;
  icon?: LucideIcon | React.ComponentType<{ className?: string }>;
  badge?: string;
  action?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
  minHeight?: string;
  className?: string;
}

export const ChartCard: React.FC<ChartCardProps> = ({
  title,
  subtitle,
  icon: Icon = BarChart3,
  badge,
  action,
  footer,
  children,
  minHeight = 'min-h-[260px]',
  className,
}) => {
  return (
    <div
      className={cn(
        'rounded-xl border border-slate-800 bg-[#0F172A]/90 p-4 sm:p-5 shadow-lg backdrop-blur-sm flex flex-col justify-between font-mono',
        className
      )}
    >
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-800/80 mb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-950/70 border border-cyan-800/60 text-cyan-400">
            <Icon className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 tracking-wide">
                {title}
              </h3>
              {badge && (
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 font-semibold">
                  {badge}
                </span>
              )}
            </div>
            {subtitle && (
              <p className="text-xs text-slate-400 mt-0.5">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        {action && (
          <div className="flex items-center gap-2 self-start sm:self-auto">
            {action}
          </div>
        )}
      </div>

      {/* Chart Body Container */}
      <div className={cn('flex-1 w-full flex items-center justify-center', minHeight)}>
        {children}
      </div>

      {/* Optional Footer Metric */}
      {footer && (
        <div className="pt-3 border-t border-slate-800/80 mt-3 text-xs text-slate-400">
          {footer}
        </div>
      )}
    </div>
  );
};
