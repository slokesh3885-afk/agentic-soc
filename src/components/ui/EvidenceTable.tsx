import React, { useState } from 'react';
import type { CanonicalEvidenceItem, EvidenceItem } from '../../types/soc';
import {
  Copy,
  Check,
  Eye,
  Search,
  Fingerprint,
} from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { Button } from './Button';
import { cn } from '../../lib/utils';

export interface EvidenceTableProps {
  evidence: Array<CanonicalEvidenceItem | EvidenceItem | any>;
  onViewEvidence?: (item: any) => void;
  maxRows?: number;
  compact?: boolean;
  showHash?: boolean;
  searchable?: boolean;
  className?: string;
  title?: string;
}

export const EvidenceTable: React.FC<EvidenceTableProps> = ({
  evidence = [],
  onViewEvidence,
  maxRows,
  compact: _compact = false,
  showHash = true,
  searchable = true,
  className,
  title = 'Cryptographic Evidence Ledger',
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const filteredEvidence = evidence.filter((item) => {
    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    const id = (item.evidence_id || item.id || '').toLowerCase();
    const type = (item.evidence_type || item.type || '').toLowerCase();
    const source = (item.source || '').toLowerCase();
    const content = (item.raw_output || item.content || '').toLowerCase();
    return id.includes(q) || type.includes(q) || source.includes(q) || content.includes(q);
  });

  const displayedRows = maxRows ? filteredEvidence.slice(0, maxRows) : filteredEvidence;

  return (
    <div
      className={cn(
        'rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden shadow-xl font-mono text-xs flex flex-col',
        className
      )}
    >
      {/* Table Header Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-[#0E1526] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-slate-200 text-xs uppercase tracking-wide">
            {title}
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-800/60 text-cyan-300 font-semibold">
            {evidence.length} artifact{evidence.length !== 1 ? 's' : ''}
          </span>
        </div>

        {searchable && (
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search evidence ID, type, source..."
              className="w-full pl-8 pr-3 py-1 bg-slate-900/90 border border-slate-700/80 rounded-md text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
        )}
      </div>

      {/* Table Container */}
      <div className="overflow-x-auto flex-1">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-900/80 text-[10px] font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <th className="py-2.5 px-3">Evidence ID</th>
              <th className="py-2.5 px-3">Type & Source</th>
              <th className="py-2.5 px-3">Telemetry Payload / Excerpt</th>
              {showHash && <th className="py-2.5 px-3">SHA-256 Content Hash</th>}
              <th className="py-2.5 px-3">Integrity</th>
              <th className="py-2.5 px-3">Timestamp</th>
              {onViewEvidence && <th className="py-2.5 px-3 text-right">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {displayedRows.length === 0 ? (
              <tr>
                <td
                  colSpan={onViewEvidence ? 7 : 6}
                  className="py-8 text-center text-slate-500 text-xs italic"
                >
                  {searchTerm ? 'No matching evidence artifacts found.' : 'No evidence objects registered.'}
                </td>
              </tr>
            ) : (
              displayedRows.map((item, idx) => {
                const id = item.evidence_id || item.id || `EV-${idx + 1}`;
                const type = item.evidence_type || item.type || 'RAW_TELEMETRY';
                const source = item.source || 'Telemetry Ingestion';
                const content = item.raw_output || item.content || item.description || '';
                const hash = item.content_hash || item.sha256 || item.hash || '';
                const integrity = item.integrity_status || item.integrity || 'VALID';
                const timestamp = item.timestamp || item.created_at || 'Just now';

                return (
                  <tr
                    key={id}
                    className="hover:bg-slate-800/40 transition-colors group"
                  >
                    {/* Evidence ID with copy */}
                    <td className="py-2.5 px-3 font-bold text-cyan-400 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span>{id}</span>
                        <button
                          onClick={() => copyToClipboard(id, `id-${id}`)}
                          className="opacity-0 group-hover:opacity-100 p-0.5 text-slate-400 hover:text-cyan-300 transition-opacity"
                          title="Copy Evidence ID"
                        >
                          {copiedId === `id-${id}` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* Type & Source */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="flex flex-col">
                        <span className="font-semibold text-slate-200">{type}</span>
                        <span className="text-[10px] text-slate-400">{source}</span>
                      </div>
                    </td>

                    {/* Excerpt */}
                    <td className="py-2.5 px-3 max-w-xs truncate text-slate-300">
                      <span className="truncate block" title={content}>
                        {content ? content.slice(0, 75) + (content.length > 75 ? '...' : '') : '—'}
                      </span>
                    </td>

                    {/* SHA-256 Hash */}
                    {showHash && (
                      <td className="py-2.5 px-3 whitespace-nowrap font-mono text-[10px] text-slate-400">
                        {hash ? (
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-400" title={hash}>
                              {hash.slice(0, 10)}...{hash.slice(-8)}
                            </span>
                            <button
                              onClick={() => copyToClipboard(hash, `hash-${id}`)}
                              className="opacity-0 group-hover:opacity-100 p-0.5 text-slate-400 hover:text-cyan-300 transition-opacity"
                              title="Copy SHA-256"
                            >
                              {copiedId === `hash-${id}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        ) : (
                          <span className="text-slate-600">Pending</span>
                        )}
                      </td>
                    )}

                    {/* Integrity Badge */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <StatusBadge status={integrity} size="xs" />
                    </td>

                    {/* Timestamp */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-[10px] text-slate-400">
                      {timestamp}
                    </td>

                    {/* Actions */}
                    {onViewEvidence && (
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => onViewEvidence(item)}
                          className="h-6 px-2 text-[10px] text-cyan-300 hover:bg-cyan-950/60 hover:text-cyan-200 gap-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>View</span>
                        </Button>
                      </td>
                    )}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {maxRows && filteredEvidence.length > maxRows && (
        <div className="p-2 bg-slate-900/60 border-t border-slate-800 text-center text-[10px] text-slate-400">
          Showing {maxRows} of {filteredEvidence.length} evidence artifacts
        </div>
      )}
    </div>
  );
};
