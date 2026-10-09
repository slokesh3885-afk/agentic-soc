import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  Search,
  Filter,
  Lock,
  GitCommit,
  Hash,
  Copy,
  Check,
  Clock,
  UserCheck,
  Layers,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { AuditEntry, AuditVerificationResult } from '../../types/soc';

export const AuditTrailView: React.FC = () => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verification, setVerification] = useState<AuditVerificationResult | null>(null);
  const [merkleRoot, setMerkleRoot] = useState<string>('');
  const [totalEntries, setTotalEntries] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [searchInv, setSearchInv] = useState<string>('');
  const [selectedEventType, setSelectedEventType] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadAuditData = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [entriesData, verifyData, merkleData] = await Promise.all([
        socApi.getAuditTrail({
          investigation_id: searchInv.trim() || undefined,
          event_type: selectedEventType !== 'ALL' ? selectedEventType : undefined,
          order: sortOrder,
          limit: 100,
        }),
        socApi.verifyAuditTrail(),
        socApi.getLedgerMerkleRoot(),
      ]);

      setEntries(entriesData);
      setVerification(verifyData);
      setMerkleRoot(merkleData.merkle_root);
      setTotalEntries(merkleData.total_entries);
    } catch (err: any) {
      console.error('Failed to load audit trail:', err);
      setErrorMsg(err.message || 'Failed to load audit trail ledger');
    } finally {
      setIsLoading(false);
    }
  };

  const handleManualVerify = async () => {
    setIsVerifying(true);
    try {
      const result = await socApi.verifyAuditTrail();
      setVerification(result);
    } catch (err: any) {
      console.error('Verification check error:', err);
      setErrorMsg(err.message || 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  useEffect(() => {
    loadAuditData();
  }, [searchInv, selectedEventType, sortOrder]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const getEventBadgeClass = (eventType: string) => {
    switch (eventType) {
      case 'GENESIS_BLOCK':
        return 'bg-purple-950/80 text-purple-300 border-purple-800/60';
      case 'EVIDENCE_SEALED':
        return 'bg-blue-950/80 text-blue-300 border-blue-800/60';
      case 'TOOL_INVOCATION':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      case 'CRITIC_ASSESSMENT':
        return 'bg-indigo-950/80 text-indigo-300 border-indigo-800/60';
      case 'CASE_AUDITED':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60';
      case 'HUMAN_APPROVAL':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/60';
      case 'INVESTIGATION_SEALED':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-800';
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6 select-text">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-700/60 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100 font-mono tracking-tight">
                Cryptographic Immutable Audit Trail
              </h2>
              <p className="text-xs text-slate-400">
                Module 3L • SHA-256 hash-chained append-only ledger with continuous Merkle tree integrity verification
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleManualVerify}
            disabled={isVerifying}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-700/50 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
            <span>{isVerifying ? 'Verifying Chain...' : 'Verify Cryptographic Chain'}</span>
          </button>

          <button
            onClick={loadAuditData}
            disabled={isLoading}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-slate-800 transition-all"
            title="Refresh Ledger"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Cryptographic Proof Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Card 1: Chain Integrity Status */}
        <div className="bg-[#0F172A] border border-slate-800/90 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              Chain Cryptographic State
            </span>
            {verification?.chain_valid ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/60">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                CHAIN INTACT
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700/60">
                CORRUPTED
              </span>
            )}
          </div>
          <div className="text-xs text-slate-300 leading-relaxed font-mono">
            {verification ? (
              verification.chain_valid ? (
                <span className="text-emerald-300/90">
                  {verification.total_entries} blocks verified unbroken. Zero tampered payloads or broken links detected.
                </span>
              ) : (
                <span className="text-rose-400">
                  Anomaly detected at entry {verification.corrupted_entry_id}: {verification.details}
                </span>
              )
            ) : (
              <span className="text-slate-500">Checking ledger integrity...</span>
            )}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Verified: {verification?.verification_timestamp || 'In progress'}
          </div>
        </div>

        {/* Card 2: Binary Merkle Root */}
        <div className="bg-[#0F172A] border border-slate-800/90 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-blue-400" />
              Binary Merkle Root
            </span>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-2 py-0.5 rounded">
              v1.0.0
            </span>
          </div>
          <div className="flex items-center justify-between bg-[#090D16] border border-slate-800 rounded-lg p-2 font-mono text-[11px]">
            <span className="text-slate-300 truncate mr-2" title={merkleRoot || ''}>
              {merkleRoot ? `${merkleRoot.slice(0, 16)}...${merkleRoot.slice(-12)}` : 'Computing root...'}
            </span>
            {merkleRoot && (
              <button
                onClick={() => copyToClipboard(merkleRoot, 'merkle')}
                className="text-slate-400 hover:text-slate-200"
                title="Copy Full Merkle Root"
              >
                {copiedHash === 'merkle' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            )}
          </div>
          <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between">
            <span>Deterministic SHA-256 tree over all block hashes</span>
            <span>Total Blocks: {totalEntries}</span>
          </div>
        </div>

        {/* Card 3: Monotonic Block Ledger */}
        <div className="bg-[#0F172A] border border-slate-800/90 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <GitCommit className="w-3.5 h-3.5 text-purple-400" />
              Monotonic Hash Chain
            </span>
            <span className="text-[11px] font-mono font-bold text-slate-200">
              Seq #0000 → #{String(Math.max(0, totalEntries - 1)).padStart(4, '0')}
            </span>
          </div>
          <div className="text-xs text-slate-300 space-y-1 font-mono text-[11px]">
            <div className="flex justify-between text-slate-400">
              <span>Genesis Block:</span>
              <span className="text-slate-300">AUD-0000 (Seq 0)</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Hash Link Protocol:</span>
              <span className="text-cyan-400">entry_hash → prev_hash</span>
            </div>
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Every block cryptographically binds the previous block header
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-rose-950/60 border border-rose-800/60 rounded-xl text-xs font-mono text-rose-300">
          Error: {errorMsg}
        </div>
      )}

      {/* Filters and Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-[#0F172A] border border-slate-800 p-3 rounded-xl">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchInv}
            onChange={(e) => setSearchInv(e.target.value)}
            placeholder="Filter by Investigation ID (e.g. INV-001)..."
            className="w-full bg-transparent text-xs text-slate-200 placeholder-slate-500 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center gap-2 overflow-x-auto">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <select
            value={selectedEventType}
            onChange={(e) => setSelectedEventType(e.target.value)}
            className="bg-[#090D16] border border-slate-800 text-xs text-slate-300 rounded px-2.5 py-1 focus:outline-none font-mono"
          >
            <option value="ALL">All Event Types</option>
            <option value="GENESIS_BLOCK">GENESIS_BLOCK</option>
            <option value="EVIDENCE_SEALED">EVIDENCE_SEALED</option>
            <option value="TOOL_INVOCATION">TOOL_INVOCATION</option>
            <option value="CRITIC_ASSESSMENT">CRITIC_ASSESSMENT</option>
            <option value="CASE_AUDITED">CASE_AUDITED</option>
            <option value="HUMAN_APPROVAL">HUMAN_APPROVAL</option>
            <option value="INVESTIGATION_SEALED">INVESTIGATION_SEALED</option>
          </select>

          <select
            value={sortOrder}
            onChange={(e) => setSortOrder(e.target.value as 'desc' | 'asc')}
            className="bg-[#090D16] border border-slate-800 text-xs text-slate-300 rounded px-2.5 py-1 focus:outline-none font-mono"
          >
            <option value="desc">Newest First (Desc)</option>
            <option value="asc">Chronological (Asc)</option>
          </select>
        </div>
      </div>

      {/* Audit Ledger Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="px-4 py-3 border-b border-slate-800/80 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-300 font-bold flex items-center gap-2">
            <Hash className="w-4 h-4 text-cyan-400" />
            Append-Only Audit Blocks ({entries.length} displayed)
          </span>
          <span className="text-slate-500">SHA-256 Hash Chained</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#090D16]/90 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
              <tr>
                <th className="py-2.5 px-3">Sequence</th>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Target</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Summary</th>
                <th className="py-2.5 px-3">Block SHA-256 Hash</th>
                <th className="py-2.5 px-3">Digital Seal</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {entries.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    {isLoading ? 'Loading cryptographic ledger entries...' : 'No audit entries match filter criteria.'}
                  </td>
                </tr>
              ) : (
                entries.map((entry) => (
                  <tr key={entry.id} className="hover:bg-slate-900/60 transition-colors">
                    {/* Seq */}
                    <td className="py-3 px-3">
                      <div className="font-bold text-slate-200">
                        #{String(entry.sequence).padStart(4, '0')}
                      </div>
                      <div className="text-[10px] text-slate-500">{entry.id}</div>
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{entry.timestamp}</span>
                      </div>
                    </td>

                    {/* Event Type */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${getEventBadgeClass(entry.event_type)}`}>
                        {entry.event_type}
                      </span>
                    </td>

                    {/* Target Investigation */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      {entry.investigation_id ? (
                        <span className="px-1.5 py-0.5 rounded bg-sky-950/80 text-sky-400 border border-sky-800/50 text-[11px] font-bold">
                          {entry.investigation_id}
                        </span>
                      ) : (
                        <span className="text-slate-600 text-[10px]">GLOBAL</span>
                      )}
                    </td>

                    {/* Actor */}
                    <td className="py-3 px-3 whitespace-nowrap text-slate-300 text-[11px]">
                      <div className="flex items-center gap-1.5">
                        <UserCheck className="w-3 h-3 text-slate-500" />
                        <span>{entry.actor}</span>
                      </div>
                    </td>

                    {/* Summary */}
                    <td className="py-3 px-3 text-slate-300 text-xs font-sans max-w-md">
                      {entry.payload_summary}
                    </td>

                    {/* Hashes */}
                    <td className="py-3 px-3 whitespace-nowrap text-[10px] space-y-0.5">
                      <div className="flex items-center gap-1 text-slate-300">
                        <span className="text-slate-500">Hash:</span>
                        <span className="font-mono text-cyan-300">
                          {entry.entry_hash.slice(0, 10)}...{entry.entry_hash.slice(-6)}
                        </span>
                        <button
                          onClick={() => copyToClipboard(entry.entry_hash, `eh-${entry.id}`)}
                          className="text-slate-500 hover:text-slate-300"
                          title="Copy Full Entry Hash"
                        >
                          {copiedHash === `eh-${entry.id}` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                      <div className="text-slate-600 flex items-center gap-1">
                        <span>Prev:</span>
                        <span>
                          {entry.prev_hash === '0000000000000000000000000000000000000000000000000000000000000000'
                            ? 'GENESIS_PREV_HASH'
                            : `${entry.prev_hash.slice(0, 8)}...`}
                        </span>
                      </div>
                    </td>

                    {/* Digital Seal */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        <span>{entry.signature.slice(0, 16)}</span>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
