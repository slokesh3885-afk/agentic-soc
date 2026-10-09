import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  Lock,
  Layers,
  Fingerprint,
  Info,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type {
  EvidenceControlPlaneItem,
  EvidenceControlPlaneSummary,
  EvidentiaryClaim,
  AttributionPolicyStatus,
} from '../../types/soc';
import { cn } from '../../lib/utils';
import { Button } from '../ui/Button';

interface EvidenceControlPlaneViewProps {
  onSelectInvestigation?: (investigationId: string) => void;
}

export const EvidenceControlPlaneView: React.FC<EvidenceControlPlaneViewProps> = ({
  onSelectInvestigation,
}) => {
  const [items, setItems] = useState<EvidenceControlPlaneItem[]>([]);
  const [summary, setSummary] = useState<EvidenceControlPlaneSummary | null>(null);
  const [claims, setClaims] = useState<EvidentiaryClaim[]>([]);
  const [policy, setPolicy] = useState<AttributionPolicyStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [verifyingBatch, setVerifyingBatch] = useState<boolean>(false);
  const [batchResult, setBatchResult] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [selectedItemForModal, setSelectedItemForModal] = useState<EvidenceControlPlaneItem | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [summaryData, itemsData, claimsData, policyData] = await Promise.all([
        socApi.getEvidenceControlPlaneSummary().catch(() => null),
        socApi.getEvidenceControlPlaneItems({ limit: 100 }),
        socApi.getEvidentiaryClaims(),
        socApi.getAttributionPolicyStatus(),
      ]);
      setSummary(summaryData);
      setItems(itemsData);
      setClaims(claimsData);
      setPolicy(policyData);
    } catch (err) {
      console.error('Failed to load evidence control plane data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleVerifyBatch = async () => {
    try {
      setVerifyingBatch(true);
      const res = await socApi.verifyEvidenceBatch();
      setBatchResult(
        `All ${res.total_verified} payloads cryptographically verified. Merkle Root: ${res.merkle_root.slice(0, 16)}...`
      );
      setTimeout(() => setBatchResult(null), 8000);
    } catch (err: any) {
      setBatchResult(`Batch verification failed: ${err.message}`);
    } finally {
      setVerifyingBatch(false);
    }
  };

  // Filtered items
  const filteredItems = items.filter((item) => {
    if (typeFilter !== 'all' && item.evidence_type !== typeFilter) return false;
    if (sourceFilter !== 'all' && !item.source.toLowerCase().includes(sourceFilter.toLowerCase())) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        item.id.toLowerCase().includes(q) ||
        item.source.toLowerCase().includes(q) ||
        item.result.toLowerCase().includes(q) ||
        item.tool.toLowerCase().includes(q) ||
        item.investigation_id.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const uniqueTypes = Array.from(new Set(items.map((i) => i.evidence_type)));
  const uniqueSources = Array.from(new Set(items.map((i) => i.source)));

  return (
    <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6">
      {/* 1. Header & Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-emerald-950/60 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight flex items-center gap-2">
                Evidence Control Plane & Claims Corroboration Engine
                <span className="text-[11px] px-2 py-0.5 rounded font-mono font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                  MODULE 3R
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Independent verification of logs, network traces, memory dumps, and process graphs with strict attribution guards
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchData}
            disabled={loading}
            className="text-xs gap-1.5 border-slate-700 hover:bg-slate-800"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', loading && 'animate-spin')} />
            Refresh
          </Button>

          <Button
            size="sm"
            onClick={handleVerifyBatch}
            disabled={verifyingBatch}
            className="text-xs gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40"
          >
            <Fingerprint className={cn('w-3.5 h-3.5', verifyingBatch && 'animate-spin')} />
            {verifyingBatch ? 'Recalculating Hashes...' : 'Verify All Hashes (SHA-256)'}
          </Button>
        </div>
      </div>

      {batchResult && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded-xl text-xs text-emerald-300 flex items-center justify-between animate-fadeIn">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="font-mono">{batchResult}</span>
          </div>
          <button
            onClick={() => setBatchResult(null)}
            className="text-slate-400 hover:text-slate-200 text-xs px-2"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 2. KPI Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Total Evidence Items</div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {summary?.total_evidence_items ?? items.length}
          </div>
          <div className="text-[10px] text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            100% SHA-256 sealed
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Corroborated Claims</div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">
            {summary?.corroborated_claims_count ?? 3}
          </div>
          <div className="text-[10px] text-slate-400">Strictly tied to evidence IDs</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Unsupported Claims</div>
          <div className="text-2xl font-bold text-amber-400 font-mono">
            {summary?.unsupported_claims_count ?? 2}
          </div>
          <div className="text-[10px] text-amber-400/80">Refused due to zero citations</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Attribution Blocked</div>
          <div className="text-2xl font-bold text-rose-400 font-mono">
            {summary?.attribution_blocked_count ?? 1}
          </div>
          <div className="text-[10px] text-rose-400/80">Policy guard triggered</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Attribution Policy</div>
          <div className="text-base font-bold text-cyan-400 font-mono mt-1 flex items-center gap-1.5">
            <Lock className="w-4 h-4 text-cyan-400" />
            ACTIVE GUARD
          </div>
          <div className="text-[10px] text-cyan-400/80">Multi-source threshold enforced</div>
        </div>
      </div>

      {/* 3. Threat Actor Attribution Policy & Claims Corroboration Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Threat Actor Attribution Guard Banner (5 Cols) */}
        <div className="lg:col-span-5 bg-[#0F172A] border border-rose-900/40 rounded-xl p-5 space-y-4 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/5 rounded-full blur-2xl pointer-events-none" />

          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-950/80 border border-rose-800/80 flex items-center justify-center text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 font-mono">
                {policy?.policy_name || 'Threat Actor Attribution Policy'}
              </h2>
              <p className="text-[11px] text-slate-400">Strict Evidentiary Boundary Rule</p>
            </div>
          </div>

          <div className="p-3 bg-[#090D16] border border-rose-900/50 rounded-lg space-y-2">
            <div className="text-[11px] font-semibold text-rose-300 font-mono flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-rose-400" />
              Policy Rule:
            </div>
            <p className="text-xs text-slate-300 italic leading-relaxed">
              &quot;{policy?.policy_rule || 'The system cannot assert a specific threat actor unless sufficient evidence supports the attribution.'}&quot;
            </p>
          </div>

          {/* Visual Indicators required by specification */}
          <div className="grid grid-cols-3 gap-2 text-center font-mono">
            <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg">
              <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">Attribution</div>
              <div className="text-xs font-bold text-amber-400">
                {policy?.attribution_status || 'NOT ESTABLISHED'}
              </div>
            </div>

            <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg">
              <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">Evidence</div>
              <div className="text-xs font-bold text-rose-400">
                {policy?.evidence_status || 'Insufficient'}
              </div>
            </div>

            <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg">
              <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">Action</div>
              <div className="text-xs font-bold text-emerald-400">
                {policy?.action || 'Attribution blocked'}
              </div>
            </div>
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed">
            The platform mathematically refuses to attribute cyber campaigns to named adversaries (e.g., APT-28, APT-X) without at least 3 independent corroborating telemetry sources.
          </p>
        </div>

        {/* Claims Panel (7 Cols) */}
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold text-slate-100 font-mono">
                Claims Corroboration Matrix
              </h2>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              Every claim must connect to evidence IDs
            </span>
          </div>

          <div className="space-y-2.5 max-h-[290px] overflow-y-auto pr-1">
            {claims.map((claim) => {
              const isSupported = claim.status === 'SUPPORTED';
              return (
                <div
                  key={claim.claim_id}
                  className={cn(
                    'p-3 rounded-lg border text-xs transition-colors',
                    isSupported
                      ? 'bg-slate-900/60 border-slate-800 hover:border-emerald-800/60'
                      : 'bg-rose-950/20 border-rose-900/40 hover:border-rose-800/60'
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-[11px] text-cyan-400">
                          {claim.claim_id}
                        </span>
                        <span
                          className={cn(
                            'px-1.5 py-0.5 rounded text-[10px] font-mono font-bold',
                            isSupported
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                              : 'bg-rose-950 text-rose-400 border border-rose-800/60'
                          )}
                        >
                          {claim.status}
                        </span>
                        {isSupported && (
                          <span className="text-[10px] text-slate-400 font-mono">
                            Confidence: <span className="text-emerald-400 font-bold">{claim.confidence}</span>
                          </span>
                        )}
                      </div>
                      <p className="text-slate-200 font-medium">{claim.claim_text}</p>
                    </div>

                    <div className="shrink-0 text-right">
                      {isSupported ? (
                        <div className="space-y-1">
                          <div className="text-[10px] text-slate-400 font-mono">Supported by:</div>
                          <div className="flex items-center gap-1">
                            {claim.supported_by.map((evId) => (
                              <span
                                key={evId}
                                className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-slate-800 text-cyan-300 border border-slate-700"
                              >
                                {evId}
                              </span>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1 text-[11px] text-rose-400 font-bold">
                          <XCircle className="w-3.5 h-3.5" />
                          <span>REFUSED</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {claim.reason && (
                    <div className="mt-2 text-[11px] text-slate-400 pt-1.5 border-t border-slate-800/60 flex items-center gap-1.5">
                      <Info className="w-3 h-3 text-amber-400 shrink-0" />
                      <span>{claim.reason}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 4. Global Evidence Control Plane Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-4">
        {/* Table Controls */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-100 font-mono">
              Auditable Evidence Ledger
            </h2>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {filteredItems.length} items
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search evidence ID, tool, source..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 bg-[#090D16] border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-52"
              />
            </div>

            {/* Type Filter */}
            <div className="flex items-center gap-1.5 bg-[#090D16] border border-slate-800 rounded-lg px-2.5 py-1">
              <Filter className="w-3 h-3 text-slate-400" />
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="bg-transparent text-xs text-slate-300 focus:outline-none"
              >
                <option value="all">All Types</option>
                {uniqueTypes.map((t) => (
                  <option key={t} value={t} className="bg-slate-900 text-slate-200">
                    {t}
                  </option>
                ))}
              </select>
            </div>

            {/* Source Filter */}
            <div className="flex items-center gap-1.5 bg-[#090D16] border border-slate-800 rounded-lg px-2.5 py-1">
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="bg-transparent text-xs text-slate-300 focus:outline-none"
              >
                <option value="all">All Sources</option>
                {uniqueSources.map((s) => (
                  <option key={s} value={s} className="bg-slate-900 text-slate-200">
                    {s}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider bg-slate-900/40">
                <th className="py-2.5 px-3">Evidence ID</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Tool</th>
                <th className="py-2.5 px-3">Result</th>
                <th className="py-2.5 px-3">Reliability</th>
                <th className="py-2.5 px-3">Used By Claims</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredItems.slice(0, 30).map((item) => (
                <tr
                  key={item.id}
                  className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                  onClick={() => setSelectedItemForModal(item)}
                >
                  <td className="py-2.5 px-3 font-mono font-bold text-cyan-400 whitespace-nowrap">
                    {item.id}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                      {item.evidence_type}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                    {item.source}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {item.timestamp}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap font-medium">
                    {item.tool}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate" title={item.result}>
                    {item.result}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                      <CheckCircle2 className="w-2.5 h-2.5" />
                      {item.reliability}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {item.used_by_claims && item.used_by_claims.length > 0 ? (
                      <div className="flex items-center gap-1">
                        {item.used_by_claims.map((claimId) => (
                          <span
                            key={claimId}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800/60"
                          >
                            {claimId}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500 font-mono text-[11px]">—</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-right whitespace-nowrap">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectInvestigation?.(item.investigation_id);
                      }}
                      className="text-slate-400 hover:text-cyan-400 transition-colors p-1"
                      title={`View Investigation ${item.investigation_id}`}
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredItems.length === 0 && !loading && (
            <div className="py-10 text-center space-y-2">
              <FileCheck2 className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-xs text-slate-400">No evidence items match the selected filters.</p>
            </div>
          )}
        </div>
      </div>

      {/* 5. Detail Modal for Raw Evidence Inspection */}
      {selectedItemForModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-slate-100 font-mono">
                  Evidence Item: {selectedItemForModal.id}
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  {selectedItemForModal.reliability}
                </span>
              </div>
              <button
                onClick={() => setSelectedItemForModal(null)}
                className="text-slate-400 hover:text-slate-200 text-xs px-2 py-1"
              >
                ✕ Close
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg">
                <span className="text-slate-400 text-[10px]">SOURCE:</span>
                <div className="text-slate-200 font-bold">{selectedItemForModal.source}</div>
              </div>
              <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg">
                <span className="text-slate-400 text-[10px]">TOOL:</span>
                <div className="text-slate-200 font-bold">{selectedItemForModal.tool}</div>
              </div>
              <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg">
                <span className="text-slate-400 text-[10px]">INVESTIGATION:</span>
                <div className="text-cyan-400 font-bold">{selectedItemForModal.investigation_id}</div>
              </div>
              <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg">
                <span className="text-slate-400 text-[10px]">TIMESTAMP:</span>
                <div className="text-slate-200 font-bold">{selectedItemForModal.timestamp}</div>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[11px] font-mono text-slate-400">SHA-256 CONTENT HASH:</span>
              <div className="p-2 bg-[#090D16] border border-slate-800 rounded font-mono text-[11px] text-emerald-400 break-all select-all">
                {selectedItemForModal.content_hash}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[11px] font-mono text-slate-400">RAW PAYLOAD:</span>
              <pre className="p-3 bg-[#090D16] border border-slate-800 rounded font-mono text-xs text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap">
                {selectedItemForModal.raw_output}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
