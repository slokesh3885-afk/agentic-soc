import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  Sliders,
  Database,
  Cpu,
  RefreshCw,
  Save,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Lock,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { SocSystemSettings, TrustScoreWeights } from '../../types/soc';

interface SettingsControlPlaneViewProps {
  showToast?: (message: string) => void;
}

export const SettingsControlPlaneView: React.FC<SettingsControlPlaneViewProps> = ({ showToast }) => {
  const [settings, setSettings] = useState<SocSystemSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form states
  const [toolRegistryEnforcement, setToolRegistryEnforcement] = useState(true);
  const [attributionStrictness, setAttributionStrictness] = useState('STRICT');
  const [minAttributionEvidence, setMinAttributionEvidence] = useState(3);
  const [maxExecutionTimeout, setMaxExecutionTimeout] = useState(120);
  const [websocketTelemetry, setWebsocketTelemetry] = useState(true);
  const [merkleSealing, setMerkleSealing] = useState(true);

  // Weights
  const [weights, setWeights] = useState<TrustScoreWeights>({
    evidence_coverage: 0.35,
    evidence_quality: 0.25,
    contradiction_handling: 0.20,
    attribution_support: 0.10,
    replay_consistency: 0.10,
  });

  const loadSettings = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const res = await socApi.getSystemSettings();
      setSettings(res);
      setToolRegistryEnforcement(res.tool_registry_enforcement);
      setAttributionStrictness(res.attribution_policy_strictness);
      setMinAttributionEvidence(res.min_attribution_evidence_count);
      setMaxExecutionTimeout(res.max_tool_execution_timeout_sec);
      setWebsocketTelemetry(res.websocket_telemetry_active);
      setMerkleSealing(res.merkle_sealing_enabled);
      if (res.trust_score_weights) {
        setWeights(res.trust_score_weights);
      }
    } catch (err: any) {
      console.error('Failed to load system settings:', err);
      setError(err?.message || 'Failed to connect to FastAPI backend');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const totalWeight =
    Math.round(
      (weights.evidence_coverage +
        weights.evidence_quality +
        weights.contradiction_handling +
        weights.attribution_support +
        weights.replay_consistency) *
        100
    ) / 100;

  const handleNormalizeWeights = () => {
    const sum =
      weights.evidence_coverage +
      weights.evidence_quality +
      weights.contradiction_handling +
      weights.attribution_support +
      weights.replay_consistency;

    if (sum === 0) return;

    setWeights({
      evidence_coverage: Math.round((weights.evidence_coverage / sum) * 100) / 100,
      evidence_quality: Math.round((weights.evidence_quality / sum) * 100) / 100,
      contradiction_handling: Math.round((weights.contradiction_handling / sum) * 100) / 100,
      attribution_support: Math.round((weights.attribution_support / sum) * 100) / 100,
      replay_consistency: Math.round((weights.replay_consistency / sum) * 100) / 100,
    });
  };

  const handleSave = async () => {
    try {
      setIsSaving(true);
      setError(null);
      const updated = await socApi.updateSystemSettings({
        tool_registry_enforcement: toolRegistryEnforcement,
        attribution_policy_strictness: attributionStrictness,
        min_attribution_evidence_count: minAttributionEvidence,
        max_tool_execution_timeout_sec: maxExecutionTimeout,
        websocket_telemetry_active: websocketTelemetry,
        merkle_sealing_enabled: merkleSealing,
        trust_score_weights: weights,
      });
      setSettings(updated);
      setSaveSuccess(true);
      if (showToast) {
        showToast('Enterprise SOC Control Plane settings updated successfully!');
      }
      setTimeout(() => setSaveSuccess(false), 3500);
    } catch (err: any) {
      console.error('Failed to save settings:', err);
      setError(err?.message || 'Failed to update system settings');
    } finally {
      setIsSaving(false);
    }
  };

  const handleResetDefaults = async () => {
    if (!window.confirm('Reset all SOC Control Plane settings to factory defaults?')) {
      return;
    }
    try {
      setIsLoading(true);
      const reset = await socApi.resetSystemSettings();
      setSettings(reset);
      setToolRegistryEnforcement(reset.tool_registry_enforcement);
      setAttributionStrictness(reset.attribution_policy_strictness);
      setMinAttributionEvidence(reset.min_attribution_evidence_count);
      setMaxExecutionTimeout(reset.max_tool_execution_timeout_sec);
      setWebsocketTelemetry(reset.websocket_telemetry_active);
      setMerkleSealing(reset.merkle_sealing_enabled);
      if (reset.trust_score_weights) {
        setWeights(reset.trust_score_weights);
      }
      if (showToast) {
        showToast('Settings restored to factory defaults');
      }
    } catch (err: any) {
      console.error('Failed to reset settings:', err);
      setError(err?.message || 'Failed to reset settings');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6">
      {/* Header Banner */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-cyan-950/60 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shadow-inner">
            <Sliders className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-slate-100 font-mono">
                Enterprise SOC Control Plane & Policy Engine
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/80 font-bold">
                TIER 1 & 2
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Configurable safety gates, Tool Registry allow-list enforcement, and explainable Trust Score weighting
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={loadSettings}
            disabled={isLoading}
            className="px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100 text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleResetDefaults}
            disabled={isLoading || isSaving}
            className="px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-amber-700 text-amber-400 text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Defaults
          </button>
          <button
            onClick={handleSave}
            disabled={isLoading || isSaving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs font-mono transition-all flex items-center gap-1.5 shadow-md shadow-cyan-950/50"
          >
            <Save className="w-3.5 h-3.5" />
            {isSaving ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {saveSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-2.5 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>System configuration successfully committed and broadcast via WebSockets.</span>
        </div>
      )}

      {/* Main Grid: Policy Engine & Trust Calibration */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Security Policy & Governance (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* Card 1: Core Policy Enforcement */}
          <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-5">
            <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
              <Shield className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                Security Governance & Attribution Policies
              </h3>
            </div>

            {/* Tool Registry Enforcement */}
            <div className="flex items-start justify-between gap-4 p-3.5 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-200 font-mono">
                    Tool Registry Allow-list Enforcement
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-bold">
                    6 ALLOW-LISTED
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Strictly constrains Tool Agent to safe simulated queries (<code className="text-cyan-400 font-mono">siem_search</code>, <code className="text-cyan-400 font-mono">edr_process_search</code>, <code className="text-cyan-400 font-mono">hash_lookup</code>, <code className="text-cyan-400 font-mono">sandbox_summary</code>, <code className="text-cyan-400 font-mono">whois_lookup</code>, <code className="text-cyan-400 font-mono">yara_scan</code>). Prohibits arbitrary or offensive code execution.
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
                <input
                  type="checkbox"
                  checked={toolRegistryEnforcement}
                  onChange={(e) => setToolRegistryEnforcement(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            </div>

            {/* Threat Actor Attribution Policy Strictness (Spec Lines 256-275) */}
            <div className="space-y-2.5 p-3.5 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200 font-mono">
                  Threat Actor Attribution Policy Strictness
                </span>
                <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/60">
                  {attributionStrictness}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                "The system cannot assert a specific threat actor unless sufficient evidence supports the attribution." (Spec Line 262)
              </p>
              <div className="grid grid-cols-3 gap-2 pt-1">
                {[
                  { id: 'STRICT', label: 'STRICT (Enforced)', desc: 'Blocks attribution without ≥3 corroborating sources' },
                  { id: 'MEDIUM', label: 'MEDIUM (Corroborated)', desc: 'Requires ≥2 independent evidence sources' },
                  { id: 'ADVISORY', label: 'ADVISORY (Warning)', desc: 'Allows assertions with visible UNSUPPORTED flag' },
                ].map((mode) => (
                  <button
                    key={mode.id}
                    onClick={() => setAttributionStrictness(mode.id)}
                    className={`p-2.5 rounded-lg border text-left transition-all ${
                      attributionStrictness === mode.id
                        ? 'bg-cyan-950/70 border-cyan-600 text-cyan-200 shadow-md'
                        : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold font-mono">{mode.label}</div>
                    <div className="text-[10px] text-slate-400 mt-1 leading-snug">{mode.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Minimum Attribution Evidence Count */}
            <div className="flex items-center justify-between gap-4 p-3.5 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <div>
                <span className="text-xs font-bold text-slate-200 font-mono">
                  Minimum Independent Corroborations for Attribution
                </span>
                <p className="text-[11px] text-slate-400">
                  Minimum discrete verified evidence artifacts required before threat actor attribution is accepted.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={10}
                  value={minAttributionEvidence}
                  onChange={(e) => setMinAttributionEvidence(parseInt(e.target.value) || 1)}
                  className="w-16 px-2.5 py-1 rounded bg-slate-950 border border-slate-700 text-cyan-300 font-mono text-xs text-center outline-none focus:border-cyan-500"
                />
                <span className="text-xs text-slate-500 font-mono">items</span>
              </div>
            </div>

            {/* Merkle Tree Sealing */}
            <div className="flex items-start justify-between gap-4 p-3.5 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <div className="space-y-1">
                <span className="text-xs font-bold text-slate-200 font-mono">
                  Cryptographic Binary Merkle Tree Sealing
                </span>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Automatically calculates binary SHA-256 Merkle root and seals closed investigations into immutable cryptographic audit ledger.
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
                <input
                  type="checkbox"
                  checked={merkleSealing}
                  onChange={(e) => setMerkleSealing(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            </div>

            {/* Max Tool Execution Timeout */}
            <div className="flex items-center justify-between gap-4 p-3.5 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <div>
                <span className="text-xs font-bold text-slate-200 font-mono">
                  Max Sandboxed Tool Execution Timeout
                </span>
                <p className="text-[11px] text-slate-400">
                  Kill boundary for long-running SIEM queries or YARA sandbox inspections.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={10}
                  max={300}
                  step={10}
                  value={maxExecutionTimeout}
                  onChange={(e) => setMaxExecutionTimeout(parseInt(e.target.value))}
                  className="w-28 accent-cyan-500"
                />
                <span className="text-xs font-mono text-cyan-300 w-12 text-right">
                  {maxExecutionTimeout}s
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Explainable Trust Score Calibration (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-bold text-slate-100 font-mono">
                  Explainable Trust Score Weights
                </h3>
              </div>
              <span
                className={`text-xs font-mono px-2 py-0.5 rounded border ${
                  totalWeight === 1.0
                    ? 'bg-emerald-950 text-emerald-400 border-emerald-800/60 font-bold'
                    : 'bg-amber-950 text-amber-400 border-amber-800/60'
                }`}
              >
                Sum: {Math.round(totalWeight * 100)}%
              </span>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed">
              "Create an explainable trust score, NOT just an arbitrary AI confidence number." (Spec Line 347)
            </p>

            {/* Sliders for 5 Trust Factors */}
            <div className="space-y-4">
              {[
                {
                  key: 'evidence_coverage',
                  label: 'Evidence Coverage Weight',
                  desc: 'Proportion of claims supported by verified artifacts',
                  val: weights.evidence_coverage,
                },
                {
                  key: 'evidence_quality',
                  label: 'Evidence Quality Weight',
                  desc: 'Reliability and hash verification of telemetry sources',
                  val: weights.evidence_quality,
                },
                {
                  key: 'contradiction_handling',
                  label: 'Contradiction Handling Weight',
                  desc: 'Critic Agent penalty resolution for conflicting indicators',
                  val: weights.contradiction_handling,
                },
                {
                  key: 'attribution_support',
                  label: 'Attribution Support Weight',
                  desc: 'Adherence to Threat Actor Attribution Policy threshold',
                  val: weights.attribution_support,
                },
                {
                  key: 'replay_consistency',
                  label: 'Replay Consistency Weight',
                  desc: 'Deterministic forensic reproducibility score',
                  val: weights.replay_consistency,
                },
              ].map((item) => (
                <div key={item.key} className="space-y-1.5 p-3 rounded-lg bg-slate-900/40 border border-slate-800/60">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-300 font-medium">{item.label}</span>
                    <span className="text-cyan-300 font-bold">{Math.round(item.val * 100)}%</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={1}
                    step={0.05}
                    value={item.val}
                    onChange={(e) =>
                      setWeights({
                        ...weights,
                        [item.key]: parseFloat(e.target.value),
                      })
                    }
                    className="w-full accent-cyan-500"
                  />
                  <div className="text-[10px] text-slate-500">{item.desc}</div>
                </div>
              ))}
            </div>

            {totalWeight !== 1.0 && (
              <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/60 flex items-center justify-between gap-3 text-xs font-mono text-amber-300">
                <span>Weights sum to {Math.round(totalWeight * 100)}% (expected 100%).</span>
                <button
                  onClick={handleNormalizeWeights}
                  className="px-2.5 py-1 rounded bg-amber-900/60 hover:bg-amber-800 text-amber-200 border border-amber-700 font-bold text-[11px] transition-colors"
                >
                  Auto-Normalize
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row: System Telemetry & Diagnostic Ledger */}
      <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
          <Database className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-100 font-mono">
            FastAPI Backend & Cryptographic Engine Telemetry
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
            <div className="text-slate-400">Database Engine</div>
            <div className="text-emerald-400 font-bold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              SQLite Persistent
            </div>
            <div className="text-[10px] text-slate-500 truncate">
              {settings?.database_path || 'backend/agentic_soc.db'}
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
            <div className="text-slate-400">Backend Version</div>
            <div className="text-cyan-300 font-bold flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5" />
              v{settings?.backend_version || '0.17.0'}
            </div>
            <div className="text-[10px] text-slate-500">FastAPI ASGI Port 8000</div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
            <div className="text-slate-400">Audit Ledger Sealing</div>
            <div className="text-emerald-400 font-bold flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              SHA-256 Merkle Root
            </div>
            <div className="text-[10px] text-slate-500">Hash-Chained Blocks</div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
            <div className="text-slate-400">Multi-Agent Swarm</div>
            <div className="text-indigo-400 font-bold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-indigo-400" />
              5 Core Agents Online
            </div>
            <div className="text-[10px] text-slate-500">Planner, Tool, Analyst, Critic, Auditor</div>
          </div>
        </div>
      </div>
    </div>
  );
};
