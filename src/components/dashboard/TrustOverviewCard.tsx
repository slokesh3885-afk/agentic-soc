import type { EvidenceTrustMetric } from '../../types/soc';
import { ShieldCheck } from 'lucide-react';
import { TrustScoreBar, TrustScoreLegend } from '../ui/TrustScoreBar';
import { cn } from '../../lib/utils';

interface TrustOverviewCardProps {
  metrics: EvidenceTrustMetric[];
  onSelectInvestigation?: (id: string) => void;
}

export const TrustOverviewCard: React.FC<TrustOverviewCardProps> = ({
  metrics,
  onSelectInvestigation,
}) => {
  return (
    <div className="bg-[#0F172A]/90 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm flex flex-col h-full shadow-lg">
      {/* Header */}
      <div className="pb-3 border-b border-slate-800/80 mb-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Trust Overview — Evidence Trust Scores</span>
          </h2>
          <span className="text-[10px] font-mono uppercase bg-emerald-950/70 border border-emerald-700/60 text-emerald-300 px-2 py-0.5 rounded">
            Auditable Multi-Source
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Cryptographically & telemetry-verified corroboration index across active cases
        </p>
      </div>

      {/* Critical Clarification Notice */}
      <div className="mb-4">
        <TrustScoreLegend />
      </div>

      {/* Trust Score List */}
      <div className="space-y-3.5 flex-1 overflow-y-auto pr-1">
        {metrics.map((metric) => {
          const isHigh = metric.score >= 85;
          const isMedium = metric.score >= 65 && metric.score < 85;

          return (
            <div
              key={metric.investigationId}
              onClick={() => onSelectInvestigation && onSelectInvestigation(metric.investigationId)}
              className={cn(
                'p-3 rounded-lg border bg-[#0B0F19]/60 transition-all hover:bg-slate-800/50 cursor-pointer',
                isHigh
                  ? 'border-slate-800/80 hover:border-emerald-800/60'
                  : isMedium
                  ? 'border-slate-800/80 hover:border-cyan-800/60'
                  : 'border-amber-900/40 hover:border-amber-700/60'
              )}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-400">
                    {metric.investigationId}
                  </span>
                  <span className="text-xs text-slate-200 font-medium truncate max-w-[180px] sm:max-w-[220px]">
                    {metric.alertTitle}
                  </span>
                </div>
                <span
                  className={cn(
                    'font-mono text-xs font-bold px-2 py-0.5 rounded',
                    isHigh
                      ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-700/50'
                      : isMedium
                      ? 'bg-cyan-950/70 text-cyan-400 border border-cyan-700/50'
                      : 'bg-amber-950/70 text-amber-400 border border-amber-700/50'
                  )}
                >
                  {metric.score}%
                </span>
              </div>

              {/* Progress Bar */}
              <TrustScoreBar score={metric.score} showLabel={false} size="sm" />

              {/* Telemetry Breakdown Details */}
              <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                <span className="truncate max-w-[200px]" title={metric.primaryCorroborator}>
                  Source: {metric.primaryCorroborator}
                </span>
                <span className="text-slate-400 shrink-0">
                  {metric.verifiedArtifactsCount}/{metric.totalArtifactsCount} artifacts verified
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
