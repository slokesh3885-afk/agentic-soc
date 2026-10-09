import React, { useState, useEffect, useCallback } from 'react';
import type { EvidenceItem } from '../../types/soc';
import { socApi } from '../../lib/api';
import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Terminal,
  Copy,
  Check,
  RefreshCw,
  Plus,
  X,
  FileCode,
  Fingerprint,
} from 'lucide-react';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';

interface EvidenceEngineSectionProps {
  investigationId: string;
  onEvidenceAdded?: (newCount: number) => void;
}

export const EvidenceEngineSection: React.FC<EvidenceEngineSectionProps> = ({
  investigationId,
  onEvidenceAdded,
}) => {
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationStatus, setVerificationStatus] = useState<
    Record<string, { valid: boolean; timestamp: string; recalculated?: string }>
  >({});
  const [isAddFormOpen, setIsAddFormOpen] = useState<boolean>(false);

  // New Evidence Form State
  const [formData, setFormData] = useState({
    evidenceType: 'SIEM_LOG',
    source: 'Mock SIEM',
    query: '',
    rawOutput: '',
  });
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchEvidence = useCallback(async () => {
    setIsLoading(true);
    try {
      const items = await socApi.getInvestigationEvidence(investigationId);
      setEvidenceItems(items);
      // Auto-expand first item if available
      if (items.length > 0 && !expandedId) {
        setExpandedId(items[0].id);
      }
      if (onEvidenceAdded) {
        onEvidenceAdded(items.length);
      }
    } catch (err) {
      console.error('Failed to load evidence:', err);
    } finally {
      setIsLoading(false);
    }
  }, [investigationId, expandedId, onEvidenceAdded]);

  useEffect(() => {
    fetchEvidence();
  }, [investigationId]);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleVerifyIntegrity = async (evidenceId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setVerifyingId(evidenceId);
    try {
      const result = await socApi.verifyEvidenceIntegrity(evidenceId);
      setVerificationStatus((prev) => ({
        ...prev,
        [evidenceId]: {
          valid: result.valid,
          timestamp: result.timestampVerified,
          recalculated: result.recalculatedHash,
        },
      }));
    } catch (err) {
      console.error(`Verification error for ${evidenceId}:`, err);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleCreateEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.rawOutput.trim()) {
      setFormError('Raw evidence output is required for cryptographic hashing.');
      return;
    }

    setIsSubmitting(true);
    setFormError(null);
    try {
      const created = await socApi.createEvidence(investigationId, {
        evidenceType: formData.evidenceType,
        source: formData.source,
        rawOutput: formData.rawOutput,
        query: formData.query || undefined,
        timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
        status: 'VERIFIED',
      });

      setEvidenceItems((prev) => [...prev, created]);
      setExpandedId(created.id);
      setIsAddFormOpen(false);
      setFormData({
        evidenceType: 'SIEM_LOG',
        source: 'Mock SIEM',
        query: '',
        rawOutput: '',
      });

      if (onEvidenceAdded) {
        onEvidenceAdded(evidenceItems.length + 1);
      }
    } catch (err: any) {
      setFormError(err.message || 'Failed to persist evidence object.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-3 rounded-xl bg-slate-950/70 border border-slate-800 p-4">
      {/* Evidence Section Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono">
            Evidence Engine & Telemetry Ledger
          </h3>
          <span className="text-[10px] bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 font-mono px-2 py-0.5 rounded-full font-semibold">
            {evidenceItems.length} Artifact{evidenceItems.length === 1 ? '' : 's'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchEvidence}
            disabled={isLoading}
            className="h-7 px-2 text-[11px] text-slate-400 hover:text-slate-200"
            title="Refresh evidence list from backend"
          >
            <RefreshCw className={cn('w-3 h-3', isLoading && 'animate-spin')} />
          </Button>

          <Button
            variant={isAddFormOpen ? 'secondary' : 'outline'}
            size="sm"
            onClick={() => setIsAddFormOpen(!isAddFormOpen)}
            className="h-7 text-xs border-cyan-700/60 text-cyan-300 hover:bg-cyan-950/50"
          >
            {isAddFormOpen ? (
              <>
                <X className="w-3 h-3 mr-1" />
                Cancel
              </>
            ) : (
              <>
                <Plus className="w-3 h-3 mr-1" />
                Add Evidence
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Add Evidence Mini-Form */}
      {isAddFormOpen && (
        <form
          onSubmit={handleCreateEvidence}
          className="p-3.5 bg-[#090D16] border border-cyan-900/60 rounded-xl space-y-3 animate-in fade-in duration-150"
        >
          <div className="text-[11px] font-mono text-cyan-400 font-semibold flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5" />
            Append New Cryptographic Evidence Item
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
            <div>
              <label className="block text-[10px] text-slate-400 font-mono mb-1">
                Evidence Type
              </label>
              <select
                value={formData.evidenceType}
                onChange={(e) => setFormData({ ...formData, evidenceType: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="SIEM_LOG">SIEM_LOG</option>
                <option value="PROCESS_EVENT">PROCESS_EVENT</option>
                <option value="EDR_EVENT">EDR_EVENT</option>
                <option value="DNS_EVENT">DNS_EVENT</option>
                <option value="HASH_LOOKUP">HASH_LOOKUP</option>
                <option value="SANDBOX_RESULT">SANDBOX_RESULT</option>
                <option value="WHOIS_RESULT">WHOIS_RESULT</option>
                <option value="YARA_RESULT">YARA_RESULT</option>
                <option value="FILE_EVENT">FILE_EVENT</option>
                <option value="OTHER">OTHER</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] text-slate-400 font-mono mb-1">
                Source System
              </label>
              <input
                type="text"
                value={formData.source}
                onChange={(e) => setFormData({ ...formData, source: e.target.value })}
                placeholder="e.g. Mock SIEM, CrowdStrike, Zeek"
                required
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] text-slate-400 font-mono mb-1">
              Query / Command (Optional)
            </label>
            <input
              type="text"
              value={formData.query}
              onChange={(e) => setFormData({ ...formData, query: e.target.value })}
              placeholder="e.g. host=PC-DB-TEST powershell"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-[10px] text-slate-400 font-mono mb-1">
              Raw Output (Raw string to be hashed with SHA-256) *
            </label>
            <textarea
              rows={2}
              value={formData.rawOutput}
              onChange={(e) => setFormData({ ...formData, rawOutput: e.target.value })}
              placeholder="e.g. powershell.exe executed from an unusual parent process."
              required
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {formError && (
            <div className="text-[11px] text-rose-400 bg-rose-950/40 border border-rose-800/60 p-2 rounded-lg flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setIsAddFormOpen(false)}
              className="text-xs text-slate-400"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={isSubmitting}
              className="text-xs bg-cyan-600 hover:bg-cyan-500 text-white font-mono"
            >
              {isSubmitting ? 'Computing Hash & Appending...' : 'Submit & Seal Hash'}
            </Button>
          </div>
        </form>
      )}

      {/* Loading Skeleton */}
      {isLoading && (
        <div className="py-6 text-center text-slate-400 font-mono text-xs flex items-center justify-center gap-2">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
          <span>Synchronizing immutable evidence ledger...</span>
        </div>
      )}

      {/* Empty State */}
      {!isLoading && evidenceItems.length === 0 && (
        <div className="py-6 text-center bg-[#090D16] border border-dashed border-slate-800 rounded-xl space-y-1.5 font-mono text-xs text-slate-400">
          <FileCode className="w-6 h-6 text-slate-500 mx-auto" />
          <div>No evidence items recorded for this investigation yet.</div>
          <div className="text-[10px] text-slate-500">
            Click "Add Evidence" above to ingest raw forensic telemetry.
          </div>
        </div>
      )}

      {/* Evidence Items Accordion List */}
      {!isLoading && evidenceItems.length > 0 && (
        <div className="space-y-2 font-mono text-xs">
          {evidenceItems.map((item) => {
            const isExpanded = expandedId === item.id;
            const verification = verificationStatus[item.id];
            const isVerifying = verifyingId === item.id;

            return (
              <div
                key={item.id}
                className={cn(
                  'rounded-xl border transition-all overflow-hidden',
                  isExpanded
                    ? 'bg-[#0B101D] border-cyan-800/80 shadow-md'
                    : 'bg-[#090D16] border-slate-800/90 hover:border-slate-700'
                )}
              >
                {/* Accordion Row Header */}
                <div
                  onClick={() => toggleExpand(item.id)}
                  className="p-3 cursor-pointer flex flex-wrap items-center justify-between gap-2 select-none"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {isExpanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    )}

                    {/* Evidence ID Badge */}
                    <span className="font-bold text-cyan-400 bg-cyan-950/80 border border-cyan-800/60 px-2 py-0.5 rounded text-[11px]">
                      {item.id}
                    </span>

                    {/* Evidence Type Badge */}
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-semibold">
                      {item.evidenceType}
                    </span>

                    {/* Source */}
                    <span className="text-slate-300 font-sans text-xs truncate" title={item.source}>
                      {item.source}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 ml-auto text-[11px]">
                    {/* Timestamp */}
                    <span className="text-slate-400 hidden sm:inline">{item.timestamp}</span>

                    {/* Short Hash Preview */}
                    <span
                      className="text-slate-400 font-mono text-[10px] bg-black/40 px-2 py-0.5 rounded border border-slate-800/80"
                      title={item.contentHash}
                    >
                      SHA-256:{' '}
                      <span className="text-cyan-300">
                        {item.contentHash ? `${item.contentHash.slice(0, 8)}...` : 'pending'}
                      </span>
                    </span>

                    {/* Integrity Badge */}
                    {verification?.valid ? (
                      <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-950/50 border border-emerald-800/60 px-2 py-0.5 rounded">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        VERIFIED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] text-slate-400 bg-slate-900 border border-slate-700 px-2 py-0.5 rounded">
                        {item.status || 'COLLECTED'}
                      </span>
                    )}
                  </div>
                </div>

                {/* Expanded Forensic Detail Drawer */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-800/70 space-y-3 bg-[#070A11]/60">
                    {/* Query Block */}
                    {item.query && (
                      <div>
                        <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase font-semibold mb-1">
                          <Terminal className="w-3 h-3 text-cyan-400" />
                          <span>Telemetry Query Executed</span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-black/70 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                          <code>{item.query}</code>
                        </div>
                      </div>
                    )}

                    {/* Raw Output Block */}
                    <div>
                      <div className="flex items-center justify-between text-slate-400 text-[10px] uppercase font-semibold mb-1">
                        <span className="flex items-center gap-1.5">
                          <FileCode className="w-3 h-3 text-amber-400" />
                          Raw Forensic Output (Unaltered Telemetry)
                        </span>
                        <span className="text-slate-500 font-normal">
                          {new Blob([item.rawOutput]).size} bytes
                        </span>
                      </div>
                      <div className="p-3 rounded-lg bg-black/90 border border-slate-800 text-slate-200 font-mono text-xs whitespace-pre-wrap leading-relaxed">
                        {item.rawOutput}
                      </div>
                    </div>

                    {/* SHA-256 Hash Verification Box */}
                    <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 text-[11px] font-bold text-slate-200">
                          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Cryptographic SHA-256 Digest</span>
                        </div>

                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={(e) => handleVerifyIntegrity(item.id, e)}
                            disabled={isVerifying}
                            className="h-6 text-[10px] border-cyan-800 text-cyan-300 hover:bg-cyan-950/40"
                          >
                            {isVerifying ? (
                              <>
                                <RefreshCw className="w-3 h-3 mr-1 animate-spin" />
                                Recalculating...
                              </>
                            ) : (
                              <>
                                <ShieldCheck className="w-3 h-3 mr-1 text-emerald-400" />
                                Verify Integrity
                              </>
                            )}
                          </Button>

                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(item.contentHash, item.id)}
                            className="h-6 text-[10px] text-slate-400 hover:text-slate-200"
                          >
                            {copiedHash === item.id ? (
                              <>
                                <Check className="w-3 h-3 mr-1 text-emerald-400" />
                                Copied
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3 mr-1" />
                                Copy Hash
                              </>
                            )}
                          </Button>
                        </div>
                      </div>

                      {/* Full 64-char Hash String */}
                      <div className="p-2 rounded bg-black/80 border border-slate-800/80 font-mono text-[11px] text-cyan-300 select-all break-all">
                        {item.contentHash}
                      </div>

                      {/* Verification Status Result */}
                      {verification && (
                        <div
                          className={cn(
                            'p-2 rounded-lg border text-[11px] flex items-center justify-between',
                            verification.valid
                              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                              : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
                          )}
                        >
                          <div className="flex items-center gap-1.5 font-bold">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            <span>INTEGRITY VERIFIED ✓ (Hash matches raw payload bytes)</span>
                          </div>
                          <span className="text-[10px] opacity-75 font-mono">
                            {verification.timestamp}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
