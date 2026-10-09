import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  Lock,
  Radio,
  FileCheck,
  HelpCircle,
} from 'lucide-react';
import { cn } from '../../lib/utils';

export type StatusBadgeVariant =
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'
  | 'purple'
  | 'neutral'
  | 'default';

export interface StatusBadgeProps {
  status: string;
  variant?: StatusBadgeVariant;
  size?: 'xs' | 'sm' | 'md';
  showIcon?: boolean;
  pulse?: boolean;
  className?: string;
  label?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  variant,
  size = 'sm',
  showIcon = true,
  pulse = false,
  className,
  label,
}) => {
  const normStatus = (status || '').toUpperCase().trim();

  // Automatic variant detection if not explicitly specified
  const resolvedVariant: StatusBadgeVariant =
    variant ||
    (() => {
      // Success / High quality
      if (
        [
          'HIGH_TRUST',
          'VALID',
          'SUPPORTED',
          'APPROVED',
          'CLOSED',
          'CONTAINED',
          'PASS',
          'AUDITED',
          'AUDIT_VERIFIED',
          'SEALED',
          'SECURE',
          'VERIFIED',
          'SUCCESS',
        ].includes(normStatus)
      ) {
        return 'success';
      }

      // Active / Investigating / Info
      if (
        [
          'MODERATE_TRUST',
          'INVESTIGATING',
          'ACTIVE',
          'IN_PROGRESS',
          'RUNNING',
          'ANALYZING',
          'OPEN',
          'REPLAYING',
          'ELEVATED',
        ].includes(normStatus)
      ) {
        return 'info';
      }

      // Warning / Moderate risk / Uncertain
      if (
        [
          'LOW_TRUST',
          'UNCERTAIN',
          'PENDING',
          'MEDIUM',
          'REQUIRES_REVISION',
          'OVERRIDE_REQUIRED',
          'HIGH_RISK',
        ].includes(normStatus)
      ) {
        return 'warning';
      }

      // Danger / High risk / Untrusted / Failed
      if (
        [
          'UNTRUSTED',
          'FAILED',
          'CONTRADICTED',
          'REJECTED',
          'CRITICAL',
          'HIGH',
          'ERROR',
          'UNDER_ATTACK',
          'TAMPERED',
          'UNSUPPORTED',
        ].includes(normStatus)
      ) {
        return 'danger';
      }

      // Purple / Deception / Replay
      if (['SYNTHETIC', 'TRAP', 'DECEPTION', 'REPLAY', 'SIMULATED'].includes(normStatus)) {
        return 'purple';
      }

      return 'neutral';
    })();

  const getIcon = () => {
    switch (resolvedVariant) {
      case 'success':
        if (normStatus.includes('TRUST')) return <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />;
        if (normStatus.includes('SEAL') || normStatus.includes('AUDIT')) return <FileCheck className="w-3 h-3 text-emerald-400 shrink-0" />;
        return <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />;
      case 'info':
        if (normStatus === 'ACTIVE' || normStatus === 'RUNNING') return <Activity className="w-3 h-3 text-cyan-400 shrink-0 animate-pulse" />;
        return <Radio className="w-3 h-3 text-cyan-400 shrink-0" />;
      case 'warning':
        if (normStatus.includes('PENDING')) return <Clock className="w-3 h-3 text-amber-400 shrink-0" />;
        if (normStatus.includes('UNCERTAIN')) return <HelpCircle className="w-3 h-3 text-amber-400 shrink-0" />;
        return <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />;
      case 'danger':
        if (normStatus.includes('TRUST')) return <ShieldAlert className="w-3 h-3 text-rose-400 shrink-0" />;
        if (normStatus.includes('TAMPER')) return <Lock className="w-3 h-3 text-rose-400 shrink-0" />;
        return <XCircle className="w-3 h-3 text-rose-400 shrink-0" />;
      case 'purple':
        return <Radio className="w-3 h-3 text-purple-400 shrink-0" />;
      case 'neutral':
      default:
        return <Clock className="w-3 h-3 text-slate-400 shrink-0" />;
    }
  };

  const getStyleClasses = () => {
    switch (resolvedVariant) {
      case 'success':
        return 'bg-emerald-950/70 text-emerald-300 border-emerald-700/70 shadow-emerald-950/20';
      case 'info':
        return 'bg-cyan-950/70 text-cyan-300 border-cyan-700/70 shadow-cyan-950/20';
      case 'warning':
        return 'bg-amber-950/70 text-amber-300 border-amber-700/70 shadow-amber-950/20';
      case 'danger':
        return 'bg-rose-950/70 text-rose-300 border-rose-700/70 shadow-rose-950/20';
      case 'purple':
        return 'bg-purple-950/70 text-purple-300 border-purple-700/70 shadow-purple-950/20';
      case 'neutral':
      default:
        return 'bg-slate-900/80 text-slate-300 border-slate-700/80 shadow-slate-950/20';
    }
  };

  const getSizeClasses = () => {
    switch (size) {
      case 'xs':
        return 'text-[9px] px-1.5 py-0.5 gap-1';
      case 'md':
        return 'text-xs px-3 py-1 gap-1.5';
      case 'sm':
      default:
        return 'text-[10px] px-2 py-0.5 gap-1';
    }
  };

  const displayText = label || status.replace(/_/g, ' ');

  return (
    <span
      className={cn(
        'inline-flex items-center font-mono font-semibold uppercase tracking-wider rounded-full border shadow-sm transition-all',
        getStyleClasses(),
        getSizeClasses(),
        pulse && 'animate-pulse',
        className
      )}
      title={`Status: ${displayText}`}
    >
      {showIcon && getIcon()}
      <span>{displayText}</span>
    </span>
  );
};
