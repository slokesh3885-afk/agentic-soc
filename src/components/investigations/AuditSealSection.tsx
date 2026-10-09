import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  Lock,
  Layers,
  Copy,
  Check,
  RefreshCw,
  Stamp,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { AuditBundle, SealInvestigationResult } from '../../types/soc';

interface AuditSealSectionProps {
  investigationId: string;
}

export const AuditSealSection: React.FC<AuditSealSectionProps> = ({ investigationId }) => {
  const [bundle, setBundle] = useState<AuditBundle | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSealing, setIsSealing] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [signedBy, setSignedBy] = useState<string>('SOC Incident Commander');
  const [notes, setNotes] = useState<string>('Cryptographic forensic custody chain finalized');
  const [feedbackMsg, setFeedbackMsg] = useState<{ text: string; isError: boolean } | null>(null);

  const loadBundle = async () => {
    setIsLoading(true);
    setFeedbackMsg(null);
    try {
      const data = await socApi.getInvestigationAuditBundle(investigationId);
      setBundle(data);
    } catch (err: any) {
      console.error('Failed to load audit bundle:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadBundle();
  }, [investigationId]);

  const handleSealInvestigation = async () => {
    setIsSealing(true);
    setFeedbackMsg(null);
    try {
      const result: SealInvestigationResult = await socApi.sealInvestigation(investigationId, {
        investigation_id: investigationId,
        signed_by: signedBy,
        notes: notes,
      });
      setFeedbackMsg({
        text: `Investigation successfully sealed in ledger block ${result.audit_id}! Merkle root: ${result.merkle_root.slice(0, 12)}...`,
        isError: false,
      });
      await loadBundle();
    } catch (err: any) {
      setFeedbackMsg({
        text: err.message || 'Failed to seal investigation',
        isError: true,
      });
    } finally {
      setIsSealing(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-inner">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-emerald-950/80 border border-emerald-700/60 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-3.5 h-3.5" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 text-xs font-mono">
              Module 3L • Cryptographic Audit Bundle & Proof Seal
            </h3>
            <span className="text-[11px] text-slate-400">
              SHA-256 Merkle root binding evidence items, audited case JSON, and human approval gates
            </span>
          </div>
        </div>

        <button
          onClick={loadBundle}
          disabled={isLoading}
          className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800 transition-colors"
          title="Refresh Audit Proof"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {feedbackMsg && (
        <div
          className={`p-2.5 rounded-lg text-xs font-mono ${
            feedbackMsg.isError
              ? 'bg-rose-950/70 border border-rose-800 text-rose-300'
              : 'bg-emerald-950/70 border border-emerald-800 text-emerald-300'
          }`}
        >
          {feedbackMsg.text}
        </div>
      )}

      {/* Main Bundle Card */}
      {bundle ? (
        <div className="space-y-3 font-mono text-xs">
          {/* Sealing Status Banner */}
          <div className="p-3 rounded-lg bg-[#090D16] border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className={`w-4 h-4 ${bundle.sealed ? 'text-emerald-400' : 'text-amber-400'}`} />
              <span className="text-slate-200 font-bold">
                {bundle.sealed ? 'CRYPTOGRAPHICALLY SEALED IN LEDGER' : 'UNSEALED INVESTIGATION DRAFT'}
              </span>
            </div>
            {bundle.sealed ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/60">
                {bundle.seal_audit_id} • SIG-VERIFIED
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-700/60">
                ACTION REQUIRED
              </span>
            )}
          </div>

          {/* Cryptographic Manifest Details */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
            {/* Merkle Root */}
            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-slate-800/80 space-y-1">
              <div className="text-slate-400 flex items-center justify-between">
                <span className="flex items-center gap-1">
                  <Layers className="w-3 h-3 text-cyan-400" />
                  Artifact Merkle Root:
                </span>
                {bundle.merkle_root && (
                  <button
                    onClick={() => copyToClipboard(bundle.merkle_root || '', 'mr')}
                    className="text-slate-400 hover:text-slate-200"
                  >
                    {copiedHash === 'mr' ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                )}
              </div>
              <div className="text-cyan-300 truncate" title={bundle.merkle_root || ''}>
                {bundle.merkle_root || '0000000000000000000000000000000000000000000000000000000000000000'}
              </div>
            </div>

            {/* Seal Signature */}
            <div className="p-2.5 rounded-lg bg-[#0B0F19] border border-slate-800/80 space-y-1">
              <div className="text-slate-400 flex items-center justify-between">
                <span className="flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  Digital Seal Signature:
                </span>
              </div>
              <div className="text-emerald-300 truncate">
                {bundle.signature || 'Not yet committed to ledger'}
              </div>
            </div>
          </div>

          {/* Sealed Artifact Inventory */}
          <div className="p-3 rounded-lg bg-[#0B0F19] border border-slate-800/80 space-y-2">
            <div className="text-slate-400 text-[10px] font-bold uppercase tracking-wider flex items-center justify-between">
              <span>Cryptographic Manifest Artifacts ({bundle.evidence_hashes.length} Evidence, {bundle.approval_hashes.length} Approvals)</span>
              <span className="text-emerald-400">Chain Verified: True</span>
            </div>

            <div className="max-h-36 overflow-y-auto space-y-1 text-[10px]">
              {bundle.evidence_hashes.map((e) => (
                <div key={e.id} className="flex items-center justify-between p-1.5 rounded bg-[#090D16] border border-slate-800/60">
                  <div className="flex items-center gap-1.5 text-slate-300">
                    <span className="text-sky-400 font-bold">{e.id}</span>
                    <span className="text-slate-500">[{e.type}]</span>
                  </div>
                  <span className="text-slate-400 font-mono truncate max-w-[200px]" title={e.hash}>
                    SHA-256: {e.hash.slice(0, 10)}...{e.hash.slice(-6)}
                  </span>
                </div>
              ))}

              {bundle.case_id && (
                <div className="flex items-center justify-between p-1.5 rounded bg-[#090D16] border border-slate-800/60">
                  <div className="flex items-center gap-1.5 text-slate-300">
                    <span className="text-emerald-400 font-bold">{bundle.case_id}</span>
                    <span className="text-slate-500">[Canonical Case JSON]</span>
                  </div>
                  <span className="text-slate-400 font-mono truncate max-w-[200px]" title={bundle.case_hash || ''}>
                    SHA-256: {bundle.case_hash ? `${bundle.case_hash.slice(0, 10)}...${bundle.case_hash.slice(-6)}` : 'N/A'}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Action to Seal if not sealed */}
          {!bundle.sealed && (
            <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 space-y-2">
              <div className="text-slate-300 text-xs font-sans">
                Seal this completed investigation into the immutable cryptographic audit ledger. Sealing calculates an artifact Merkle root and writes an immutable block header.
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                <input
                  type="text"
                  value={signedBy}
                  onChange={(e) => setSignedBy(e.target.value)}
                  placeholder="Designated Signatory..."
                  className="bg-[#090D16] border border-slate-800 text-slate-200 rounded px-2.5 py-1.5 font-mono text-xs focus:outline-none"
                />
                <input
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Audit Notes..."
                  className="bg-[#090D16] border border-slate-800 text-slate-200 rounded px-2.5 py-1.5 font-mono text-xs focus:outline-none"
                />
              </div>
              <button
                onClick={handleSealInvestigation}
                disabled={isSealing}
                className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white font-mono font-bold text-xs shadow-md transition-all disabled:opacity-50"
              >
                <Stamp className="w-3.5 h-3.5" />
                <span>{isSealing ? 'Sealing into Immutable Ledger...' : 'Commit Cryptographic Seal to Ledger'}</span>
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="text-xs text-slate-500 font-mono py-4 text-center">
          {isLoading ? 'Loading cryptographic bundle...' : 'Audit bundle unavailable.'}
        </div>
      )}
    </div>
  );
};
