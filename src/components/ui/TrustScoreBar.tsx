import React from 'react';
import { getTrustScoreColor, cn } from '../../lib/utils';
import { ShieldCheck, Info } from 'lucide-react';

interface TrustScoreBarProps {
  score: number;
  showLabel?: boolean;
  size?: 'sm' | 'md';
  className?: string;
}

export const TrustScoreBar: React.FC<TrustScoreBarProps> = ({
  score,
  showLabel = true,
  size = 'md',
  className,
}) => {
  const { textColor, barColor, label } = getTrustScoreColor(score);

  return (
    <div className={cn('flex flex-col gap-1', className)} title={`Evidence Trust Score: ${score}% (${label})`}>
      <div className="flex items-center justify-between text-xs">
        {showLabel && (
          <span className="flex items-center gap-1 text-[11px] font-medium text-slate-400">
            <ShieldCheck className={cn('w-3.5 h-3.5', textColor)} />
            <span>Evidence Trust Score</span>
          </span>
        )}
        <span className={cn('font-mono font-semibold', textColor, size === 'sm' ? 'text-xs' : 'text-sm')}>
          {score}%
        </span>
      </div>

      <div className={cn('w-full bg-slate-800/80 rounded-full overflow-hidden border border-slate-700/50', size === 'sm' ? 'h-1.5' : 'h-2')}>
        <div
          className={cn('h-full transition-all duration-500 rounded-full', barColor)}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>
    </div>
  );
};

export const TrustScoreLegend: React.FC = () => {
  return (
    <div className="flex items-start gap-2 p-2.5 bg-slate-900/60 border border-slate-800/80 rounded-lg text-xs text-slate-400">
      <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
      <div>
        <span className="font-semibold text-slate-200">Evidence Trust Score:</span> Corroboration fidelity computed across raw telemetry (Sysmon, Zeek, EDR, MemDumps). Distinct from generative model confidence.
      </div>
    </div>
  );
};
