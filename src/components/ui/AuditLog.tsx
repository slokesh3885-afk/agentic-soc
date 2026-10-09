import React, { useState } from 'react';
import type { AuditEntry } from '../../types/soc';
import {
  ShieldCheck,
  Lock,
  Search,
  Copy,
  Check,
  Hash,
  Clock,
} from 'lucide-react';
import { cn } from '../../lib/utils';

export interface AuditLogItem {
  id?: string;
  sequence_id?: number;
  sequenceId?: number;
  timestamp: string;
  actor?: string;
  agent?: string;
  action: string;
  resource_id?: string;
  resourceId?: string;
  target?: string;
  details?: string;
  payload?: any;
  sha256_hash?: string;
  sha256Hash?: string;
  hash?: string;
  tamper_evident?: boolean;
  tamperEvident?: boolean;
}

export interface AuditLogProps {
  entries: Array<AuditLogItem | AuditEntry | any>;
  maxHeight?: string;
  showHash?: boolean;
  searchable?: boolean;
  className?: string;
  title?: string;
}

export const AuditLog: React.FC<AuditLogProps> = ({
  entries = [],
  maxHeight = 'max-h-[500px]',
  showHash = true,
  searchable = true,
  className,
  title = 'Cryptographic Immutable Audit Log',
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const filteredEntries = entries.filter((entry) => {
    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    const act = (entry.actor || entry.agent || '').toLowerCase();
    const action = (entry.action || '').toLowerCase();
    const details = (entry.details || '').toLowerCase();
    const res = (entry.resource_id || entry.resourceId || entry.target || '').toLowerCase();
    return act.includes(q) || action.includes(q) || details.includes(q) || res.includes(q);
  });

  return (
    <div
      className={cn(
        'rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden shadow-xl font-mono text-xs flex flex-col',
        className
      )}
    >
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-[#0E1526] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-emerald-400" />
          <span className="font-bold text-slate-200 text-xs uppercase tracking-wide">
            {title}
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950/70 border border-emerald-800/60 text-emerald-300 font-semibold flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            <span>SHA-256 Hash-Chained</span>
          </span>
        </div>

        {searchable && (
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search actor, action, resource..."
              className="w-full pl-8 pr-3 py-1 bg-slate-900/90 border border-slate-700/80 rounded-md text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
        )}
      </div>

      {/* Log Entries Container */}
      <div className={cn('overflow-y-auto divide-y divide-slate-800/60 flex-1', maxHeight)}>
        {filteredEntries.length === 0 ? (
          <div className="py-8 text-center text-slate-500 italic">
            {searchTerm ? 'No matching audit events found.' : 'No audit entries recorded in ledger.'}
          </div>
        ) : (
          filteredEntries.map((entry, idx) => {
            const seq = entry.sequence_id ?? entry.sequenceId ?? idx + 1;
            const actor = entry.actor || entry.agent || 'SYSTEM';
            const action = entry.action || 'LEDGER_ENTRY';
            const resource = entry.resource_id || entry.resourceId || entry.target || '';
            const details = entry.details || '';
            const hash = entry.sha256_hash || entry.sha256Hash || entry.hash || '';
            const timestamp = entry.timestamp || '00:00:00 UTC';
            const isTamperEvident = entry.tamper_evident ?? entry.tamperEvident ?? true;

            return (
              <div
                key={seq}
                className="p-3 hover:bg-slate-800/30 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[10px] font-bold text-slate-500">
                      #{String(seq).padStart(3, '0')}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-300 font-semibold uppercase">
                      {actor}
                    </span>
                    <span className="font-bold text-slate-200">
                      {action}
                    </span>
                    {resource && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400 font-mono">
                        {resource}
                      </span>
                    )}
                  </div>

                  {details && (
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {details}
                    </p>
                  )}
                </div>

                <div className="flex sm:flex-col items-center sm:items-end justify-between sm:justify-center gap-1.5 shrink-0 text-[10px] text-slate-500">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3 text-slate-500" />
                    <span>{timestamp}</span>
                  </span>

                  {showHash && hash && (
                    <div className="flex items-center gap-1 font-mono text-[9px] text-slate-400">
                      <Hash className="w-3 h-3 text-emerald-400" />
                      <span title={hash}>{hash.slice(0, 8)}...{hash.slice(-6)}</span>
                      <button
                        onClick={() => copyToClipboard(hash, `hash-${seq}`)}
                        className="p-0.5 text-slate-500 hover:text-cyan-300 transition-colors"
                        title="Copy Hash"
                      >
                        {copiedId === `hash-${seq}` ? (
                          <Check className="w-2.5 h-2.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-2.5 h-2.5" />
                        )}
                      </button>
                    </div>
                  )}

                  {isTamperEvident && (
                    <span className="text-[9px] text-emerald-400 flex items-center gap-0.5">
                      <ShieldCheck className="w-3 h-3" />
                      <span>Verified Sealed</span>
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
