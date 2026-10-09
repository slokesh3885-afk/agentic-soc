import React from 'react';
import { cn } from '../../lib/utils';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'outline' | 'critical' | 'high' | 'medium' | 'low' | 'success' | 'info';
  children: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  className,
  variant = 'default',
  ...props
}) => {
  const variantStyles: Record<string, string> = {
    default: 'bg-slate-800 text-slate-200 border-slate-700',
    outline: 'bg-transparent text-slate-300 border-slate-700',
    critical: 'bg-rose-950/70 text-rose-300 border-rose-800/60 shadow-[0_0_8px_rgba(244,63,94,0.15)]',
    high: 'bg-amber-950/70 text-amber-300 border-amber-800/60',
    medium: 'bg-yellow-950/50 text-yellow-300 border-yellow-800/50',
    low: 'bg-blue-950/50 text-blue-300 border-blue-800/50',
    success: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/50',
    info: 'bg-cyan-950/60 text-cyan-300 border-cyan-800/50',
  };

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border transition-colors',
        variantStyles[variant] || variantStyles.default,
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
};
