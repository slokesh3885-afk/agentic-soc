import React from 'react';
import { CheckCircle2, X } from 'lucide-react';
import { cn } from '../../lib/utils';

interface ToastProps {
  message: string | null;
  onClose: () => void;
}

export const Toast: React.FC<ToastProps> = ({ message, onClose }) => {
  if (!message) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 animate-in slide-in-from-bottom-4 fade-in duration-300">
      <div className={cn(
        'flex items-center gap-3 px-4 py-3 bg-slate-900/95 border border-emerald-500/40',
        'text-emerald-300 rounded-xl shadow-2xl shadow-emerald-950/40 backdrop-blur-md min-w-[320px]'
      )}>
        <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-700/50 flex items-center justify-center shrink-0">
          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
        </div>
        <div className="flex-1">
          <div className="text-xs font-semibold uppercase tracking-wider text-emerald-400/80">SOC Action Dispatched</div>
          <div className="text-sm font-medium text-slate-100">{message}</div>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 transition-colors p-1 rounded-md hover:bg-slate-800"
          aria-label="Dismiss toast"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
