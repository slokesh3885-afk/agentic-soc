import React, { useState, useEffect, useMemo } from 'react';
import {
  FolderArchive,
  RefreshCw,
  Search,
  Filter,
  Shield,
  ShieldCheck,
  Download,
  ExternalLink,
  Lock,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Activity,
  Layers,
  Sparkles,
  Copy,
  Check,
  ChevronRight,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type {
  IncidentDossier,
  MitreMatrixSummary,
  DossierNavigatorLayer,
  SeverityLevel,
} from '../../types/soc';

interface CasesDossierViewProps {
  onSelectInvestigation?: (investigationId: string) => void;
}

export const CasesDossierView: React.FC<CasesDossierViewProps> = ({
  onSelectInvestigation,
}) => {
  const [dossiers, setDossiers] = useState<IncidentDossier[]>([]);
  const [matrixSummary, setMatrixSummary] = useState<MitreMatrixSummary | null>(null);
  const [selectedDossierId, setSelectedDossierId] = useState<string | null>(null);
  const [selectedTab, setSelectedTab] = useState<'mitre' | 'custody' | 'recommendations' | 'navigator'>('mitre');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [tacticFilter, setTacticFilter] = useState<string>('ALL');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [navigatorLayer, setNavigatorLayer] = useState<DossierNavigatorLayer | null>(null);
  const [exportingNav, setExportingNav] = useState<boolean>(false);

  // Load dossiers & matrix summary
  const loadData = async () => {
    setIsLoading(true);
    try {
      const [dossiersData, summaryData] = await Promise.all([
        socApi.getDossiers(),
        socApi.getMitreMatrixSummary(),
      ]);
      setDossiers(dossiersData);
      setMatrixSummary(summaryData);
      if (dossiersData.length > 0 && !selectedDossierId) {
        setSelectedDossierId(dossiersData[0].id);
      }
    } catch (err) {
      console.error('Failed to load incident dossiers:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Fetch navigator layer when selected dossier changes
  useEffect(() => {
    if (!selectedDossierId) {
      setNavigatorLayer(null);
      return;
    }
    socApi
      .getDossierNavigatorLayer(selectedDossierId)
      .then((layer) => setNavigatorLayer(layer))
      .catch((err) => console.error('Failed to fetch Navigator layer:', err));
  }, [selectedDossierId]);

  const selectedDossier = useMemo(() => {
    return dossiers.find((d) => d.id === selectedDossierId) || dossiers[0] || null;
  }, [dossiers, selectedDossierId]);

  // Handle single dossier refresh
  const handleRefreshSelected = async () => {
    if (!selectedDossier) return;
    setIsRefreshing(true);
    try {
      const updated = await socApi.refreshDossier(selectedDossier.investigation_id);
      setDossiers((prev) => prev.map((d) => (d.id === updated.id ? updated : d)));
      const summary = await socApi.getMitreMatrixSummary();
      setMatrixSummary(summary);
      const layer = await socApi.getDossierNavigatorLayer(updated.id);
      setNavigatorLayer(layer);
    } catch (err) {
      console.error('Failed to refresh dossier:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Export MITRE ATT&CK Navigator JSON
  const handleDownloadNavigator = async (dossierId?: string) => {
    const targetId = dossierId || selectedDossier?.id;
    if (!targetId) return;
    setExportingNav(true);
    try {
      const layer = await socApi.getDossierNavigatorLayer(targetId);
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(layer, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `mitre_attack_navigator_${targetId.toLowerCase()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (err) {
      console.error('Failed to download navigator layer:', err);
    } finally {
      setExportingNav(false);
    }
  };

  // Copy hash helper
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Filtered dossiers
  const filteredDossiers = useMemo(() => {
    return dossiers.filter((d) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        d.id.toLowerCase().includes(q) ||
        d.investigation_id.toLowerCase().includes(q) ||
        d.title.toLowerCase().includes(q) ||
        d.primary_tactic.toLowerCase().includes(q) ||
        (d.threat_actor_attribution && d.threat_actor_attribution.toLowerCase().includes(q)) ||
        d.mitre_techniques.some(
          (t) => t.technique_id.toLowerCase().includes(q) || t.technique_name.toLowerCase().includes(q)
        );

      const matchesSeverity =
        severityFilter === 'ALL' || d.severity.toLowerCase() === severityFilter.toLowerCase();

      const matchesTactic =
        tacticFilter === 'ALL' || d.primary_tactic.toLowerCase() === tacticFilter.toLowerCase();

      return matchesSearch && matchesSeverity && matchesTactic;
    });
  }, [dossiers, searchQuery, severityFilter, tacticFilter]);

  const severityBadge = (severity: SeverityLevel | string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-950/80 text-red-400 border-red-800/80';
      case 'high':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/80';
      case 'medium':
        return 'bg-yellow-950/80 text-yellow-400 border-yellow-800/80';
      default:
        return 'bg-blue-950/80 text-blue-400 border-blue-800/80';
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-lg bg-cyan-950/60 border border-cyan-800/60 flex items-center justify-center text-cyan-400 shadow-inner">
            <FolderArchive className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-lg font-bold text-slate-100">
                Incident Cases Dossier & MITRE ATT&CK Matrix
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800/80">
                Module 3M
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-800/80 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                ATT&CK {matrixSummary?.matrix_version || 'v14.1'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Enterprise MITRE ATT&CK technique mapping, chronological chain-of-custody transfer ledger, and ATT&CK Navigator layer generation.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
            title="Reload all dossiers"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Reload</span>
          </button>

          <button
            onClick={() => handleDownloadNavigator()}
            disabled={!selectedDossier || exportingNav}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-cyan-200 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/80 rounded-lg transition-colors shadow-sm disabled:opacity-50"
            title="Export MITRE ATT&CK Navigator JSON layer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Navigator Layer</span>
          </button>
        </div>
      </div>

      {/* KPI Analytics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Incident Dossiers</span>
            <FolderArchive className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {matrixSummary?.total_dossiers || dossiers.length}
          </div>
          <div className="text-[11px] text-slate-500 font-mono flex items-center gap-1">
            <span>100% backed by persistent case schema</span>
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Mapped Techniques</span>
            <Layers className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {matrixSummary?.total_techniques_mapped || 0}
          </div>
          <div className="text-[11px] text-emerald-400/90 font-mono flex items-center gap-1">
            <span>Verified via evidence telemetry</span>
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Enterprise Tactics</span>
            <Activity className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {matrixSummary?.coverage?.filter((c) => c.technique_count > 0).length || 0}
            <span className="text-sm font-normal text-slate-500"> / 14</span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono">
            ATT&CK Enterprise Matrix v14.1
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Chain of Custody Events</span>
            <ShieldCheck className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {dossiers.reduce((acc, d) => acc + (d.custody_chain?.length || 0), 0)}
          </div>
          <div className="text-[11px] text-blue-400/90 font-mono flex items-center gap-1">
            <Lock className="w-3 h-3" />
            <span>Cryptographically sealed & verifiable</span>
          </div>
        </div>
      </div>

      {/* 14 Enterprise Tactics Interactive Coverage Grid */}
      {matrixSummary?.coverage && (
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300 font-semibold">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>MITRE Enterprise ATT&CK Matrix (14 Tactics Coverage)</span>
            </div>
            {tacticFilter !== 'ALL' && (
              <button
                onClick={() => setTacticFilter('ALL')}
                className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1"
              >
                <span>Reset Tactic Filter ({tacticFilter})</span>
              </button>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
            {matrixSummary.coverage.map((tactic) => {
              const count = tactic.technique_count;
              const isSelected = tacticFilter.toLowerCase() === tactic.tactic_name.toLowerCase();
              return (
                <button
                  key={tactic.tactic_id}
                  onClick={() =>
                    setTacticFilter(isSelected ? 'ALL' : tactic.tactic_name)
                  }
                  className={`text-left p-2.5 rounded-lg border transition-all ${
                    isSelected
                      ? 'bg-cyan-950/80 border-cyan-500 shadow-md shadow-cyan-950/50'
                      : count > 0
                      ? 'bg-[#0A101D] border-slate-700/80 hover:border-slate-600'
                      : 'bg-[#070B14] border-slate-900 opacity-60 hover:opacity-90'
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span>{tactic.tactic_id}</span>
                    <span
                      className={`px-1.5 py-0.2 rounded-full font-bold ${
                        count > 0
                          ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                          : 'bg-slate-900 text-slate-500'
                      }`}
                    >
                      {count}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-slate-200 truncate mt-1">
                    {tactic.tactic_name}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#0F172A] border border-slate-800 rounded-xl p-3">
        <div className="relative w-full sm:w-96">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search dossier, investigation, technique or actor..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#090D16] border border-slate-700 text-xs text-slate-200 pl-9 pr-3 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500 placeholder-slate-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
            <Filter className="w-3.5 h-3.5" />
            <span>Severity:</span>
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#090D16] border border-slate-700 text-xs text-slate-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {/* Master-Detail Split: Left Dossier List, Right Dossier Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Dossier Cards (5 cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400 px-1 font-mono">
            <span>Case Dossiers ({filteredDossiers.length})</span>
            <span>Select to inspect</span>
          </div>

          <div className="space-y-2.5 max-h-[750px] overflow-y-auto pr-1">
            {filteredDossiers.length === 0 ? (
              <div className="p-8 text-center bg-[#0F172A] border border-slate-800 rounded-xl text-xs text-slate-400 space-y-2">
                <FolderArchive className="w-8 h-8 text-slate-600 mx-auto" />
                <div>No case dossiers match your current filters.</div>
              </div>
            ) : (
              filteredDossiers.map((d) => {
                const isSelected = selectedDossier?.id === d.id;
                return (
                  <div
                    key={d.id}
                    onClick={() => setSelectedDossierId(d.id)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-[#131F37] border-cyan-500 shadow-md shadow-cyan-950/50'
                        : 'bg-[#0F172A] border-slate-800 hover:border-slate-700 hover:bg-[#111B30]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-mono mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-400 font-bold">{d.id}</span>
                        <span className="text-slate-500">•</span>
                        <span className="text-slate-300">{d.investigation_id}</span>
                      </div>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold ${severityBadge(d.severity)}`}>
                        {d.severity}
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-slate-100 line-clamp-2 mb-2">
                      {d.title}
                    </h4>

                    <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono mb-2.5">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                        {d.primary_tactic}
                      </span>
                      {d.threat_actor_attribution && (
                        <span
                          className={`px-2 py-0.5 rounded border truncate max-w-[240px] ${
                            d.threat_actor_attribution.includes('Withheld')
                              ? 'bg-amber-950/60 text-amber-300 border-amber-800/60'
                              : 'bg-cyan-950/60 text-cyan-300 border-cyan-800/60'
                          }`}
                          title={d.threat_actor_attribution}
                        >
                          {d.threat_actor_attribution}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/80 font-mono">
                      <span>{d.mitre_techniques?.length || 0} ATT&CK Techs</span>
                      <span>{d.custody_chain?.length || 0} Custody Events</span>
                      <ChevronRight className={`w-4 h-4 transition-transform ${isSelected ? 'text-cyan-400 translate-x-0.5' : 'text-slate-600'}`} />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Dossier Detail Inspection (7 cols) */}
        <div className="lg:col-span-7">
          {selectedDossier ? (
            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-5">
              {/* Dossier Detail Header */}
              <div className="border-b border-slate-800 pb-4 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-cyan-400 font-bold text-sm">{selectedDossier.id}</span>
                    <span className="text-slate-500">•</span>
                    <button
                      onClick={() => onSelectInvestigation && onSelectInvestigation(selectedDossier.investigation_id)}
                      className="text-slate-300 hover:text-cyan-400 hover:underline flex items-center gap-1"
                      title="Open full investigation modal"
                    >
                      <span>{selectedDossier.investigation_id}</span>
                      <ExternalLink className="w-3 h-3 text-slate-500" />
                    </button>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold ${severityBadge(selectedDossier.severity)}`}>
                      {selectedDossier.severity}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                      {selectedDossier.status}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleRefreshSelected}
                      disabled={isRefreshing}
                      className="px-2.5 py-1 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors disabled:opacity-50"
                      title="Refresh dossier analysis"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
                      <span>Refresh</span>
                    </button>

                    <button
                      onClick={() => handleDownloadNavigator(selectedDossier.id)}
                      disabled={exportingNav}
                      className="px-2.5 py-1 text-xs font-medium text-cyan-200 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/80 rounded-lg flex items-center gap-1.5 transition-colors"
                      title="Download ATT&CK Navigator JSON layer"
                    >
                      <Download className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Navigator JSON</span>
                    </button>
                  </div>
                </div>

                <h3 className="text-base font-bold text-slate-100">
                  {selectedDossier.title}
                </h3>

                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  {selectedDossier.summary}
                </p>

                {/* Threat Attribution Banner */}
                {selectedDossier.threat_actor_attribution && (
                  <div className={`p-3 rounded-lg border text-xs font-mono flex items-start gap-2.5 ${
                    selectedDossier.threat_actor_attribution.includes('Withheld')
                      ? 'bg-amber-950/40 border-amber-800/60 text-amber-300'
                      : 'bg-cyan-950/40 border-cyan-800/60 text-cyan-300'
                  }`}>
                    {selectedDossier.threat_actor_attribution.includes('Withheld') ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    )}
                    <div>
                      <div className="font-bold">Threat Actor Attribution:</div>
                      <div>{selectedDossier.threat_actor_attribution}</div>
                    </div>
                  </div>
                )}
              </div>

              {/* Sub-Navigation Tabs */}
              <div className="flex items-center gap-2 border-b border-slate-800 pb-2 text-xs font-mono">
                <button
                  onClick={() => setSelectedTab('mitre')}
                  className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors ${
                    selectedTab === 'mitre'
                      ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>ATT&CK Techniques ({selectedDossier.mitre_techniques?.length || 0})</span>
                </button>

                <button
                  onClick={() => setSelectedTab('custody')}
                  className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors ${
                    selectedTab === 'custody'
                      ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Chain of Custody ({selectedDossier.custody_chain?.length || 0})</span>
                </button>

                <button
                  onClick={() => setSelectedTab('recommendations')}
                  className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors ${
                    selectedTab === 'recommendations'
                      ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Recommendations ({selectedDossier.recommendations?.length || 0})</span>
                </button>

                <button
                  onClick={() => setSelectedTab('navigator')}
                  className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors ${
                    selectedTab === 'navigator'
                      ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Navigator JSON</span>
                </button>
              </div>

              {/* Tab 1: MITRE ATT&CK Mapping */}
              {selectedTab === 'mitre' && (
                <div className="space-y-3">
                  <div className="text-xs text-slate-400 font-mono">
                    Deterministic MITRE ATT&CK technique mapping corroborated by evidence artifacts:
                  </div>

                  <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                    {selectedDossier.mitre_techniques?.map((tech) => (
                      <div
                        key={tech.technique_id}
                        className="p-4 bg-[#090D16] border border-slate-800 rounded-lg space-y-2.5"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-cyan-400 font-mono font-bold text-xs">
                              {tech.technique_id}
                            </span>
                            <span className="text-slate-500">•</span>
                            <span className="text-slate-200 font-semibold text-xs">
                              {tech.technique_name}
                            </span>
                          </div>
                          <a
                            href={tech.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1 font-mono"
                          >
                            <span>MITRE Doc</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>

                        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            Tactic: {tech.tactic} ({tech.tactic_id})
                          </span>
                          <span className="px-2 py-0.5 rounded bg-emerald-950/70 text-emerald-400 border border-emerald-800/70">
                            Confidence: {Math.round(tech.confidence * 100)}%
                          </span>
                          {tech.evidence_ids?.map((evId) => (
                            <span
                              key={evId}
                              className="px-2 py-0.5 rounded bg-cyan-950/70 text-cyan-400 border border-cyan-800/70"
                            >
                              Evidence: {evId}
                            </span>
                          ))}
                        </div>

                        <p className="text-xs text-slate-400 leading-relaxed font-sans">
                          {tech.description}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 2: Forensic Chain of Custody */}
              {selectedTab === 'custody' && (
                <div className="space-y-3">
                  <div className="text-xs text-slate-400 font-mono">
                    Chronological chain-of-custody transfer ledger tracing origin, tool execution, multi-agent evaluation, and cryptographic seals:
                  </div>

                  <div className="space-y-2.5 max-h-[500px] overflow-y-auto pr-1">
                    {selectedDossier.custody_chain?.map((event) => (
                      <div
                        key={event.sequence}
                        className="p-3 bg-[#090D16] border border-slate-800 rounded-lg flex items-start gap-3 text-xs"
                      >
                        <div className="w-6 h-6 rounded-full bg-slate-800 text-slate-300 font-mono text-[11px] flex items-center justify-center shrink-0 border border-slate-700 font-bold">
                          {event.sequence}
                        </div>

                        <div className="space-y-1 w-full">
                          <div className="flex items-center justify-between text-xs font-mono">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-slate-200">{event.action}</span>
                              <span className="text-[10px] text-emerald-400 flex items-center gap-0.5">
                                <CheckCircle2 className="w-3 h-3" />
                                Verified
                              </span>
                            </div>
                            <span className="text-slate-500 text-[10px]">{event.timestamp}</span>
                          </div>

                          <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
                            <span>Actor: {event.actor}</span>
                            <span>•</span>
                            <span>Source: {event.source}</span>
                          </div>

                          <p className="text-xs text-slate-300 font-sans">{event.notes}</p>

                          <div className="flex items-center gap-2 pt-1 font-mono text-[10px] text-slate-500">
                            <span>Hash:</span>
                            <span className="text-slate-400 truncate max-w-[260px]">
                              {event.artifact_hash}
                            </span>
                            <button
                              onClick={() => handleCopy(event.artifact_hash)}
                              className="text-slate-400 hover:text-slate-200"
                              title="Copy artifact hash"
                            >
                              {copiedHash === event.artifact_hash ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 3: Recommendations & Attribution */}
              {selectedTab === 'recommendations' && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-200 font-mono">
                      Containment & Remediation Actions:
                    </div>
                    <div className="space-y-2">
                      {selectedDossier.recommendations?.map((rec, idx) => (
                        <div
                          key={idx}
                          className="p-3 bg-[#090D16] border border-slate-800 rounded-lg flex items-start gap-2.5 text-xs text-slate-300"
                        >
                          <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                          <span>{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 bg-[#090D16] border border-slate-800 rounded-lg space-y-2 text-xs font-mono">
                    <div className="text-slate-200 font-bold flex items-center gap-2">
                      <Lock className="w-4 h-4 text-cyan-400" />
                      <span>Forensic Accountability Verification</span>
                    </div>
                    <p className="text-slate-400 font-sans text-[11px] leading-relaxed">
                      Every claim in this dossier is bound to raw evidence IDs and tool logs recorded during execution. If the Critic Agent flags unsupported threat claims, threat attribution is safely withheld pending human review.
                    </p>
                  </div>
                </div>
              )}

              {/* Tab 4: Navigator JSON Preview */}
              {selectedTab === 'navigator' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span>MITRE ATT&CK Navigator v4.9.1 Layer (JSON):</span>
                    <button
                      onClick={() => handleDownloadNavigator(selectedDossier.id)}
                      className="text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download JSON File</span>
                    </button>
                  </div>

                  <div className="p-3 bg-[#050811] border border-slate-800 rounded-lg overflow-x-auto max-h-[450px]">
                    <pre className="text-[11px] font-mono text-slate-300 leading-tight">
                      {navigatorLayer
                        ? JSON.stringify(navigatorLayer, null, 2)
                        : '// Loading Navigator layer JSON...'}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center bg-[#0F172A] border border-slate-800 rounded-xl text-slate-400 space-y-2">
              <FolderArchive className="w-8 h-8 text-slate-600 mx-auto" />
              <div>Select an incident case dossier to view its ATT&CK matrix and forensic chain.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
