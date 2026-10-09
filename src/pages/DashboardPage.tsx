import { useSocDashboard } from '../hooks/useSocDashboard';
import { KpiCards } from '../components/dashboard/KpiCards';
import { ThreatOverviewChart } from '../components/dashboard/ThreatOverviewChart';
import { TrustOverviewCard } from '../components/dashboard/TrustOverviewCard';
import { InvestigationsTable } from '../components/dashboard/InvestigationsTable';
import { AlertsSection } from '../components/dashboard/AlertsSection';
import { TruePositiveScenarioCard } from '../components/dashboard/TruePositiveScenarioCard';
import { TrapScenarioCard } from '../components/dashboard/TrapScenarioCard';
import { LiveAgentActivityPanel } from '../components/dashboard/LiveAgentActivityPanel';
import { InteractiveDemoBar } from '../components/dashboard/InteractiveDemoBar';
import { TrustScoreCircularGauge } from '../components/ui/TrustScore';
import { ShieldCheck, CheckCircle2, Bot, Activity, Layers, Plus, Play } from 'lucide-react';
import type { SecurityAlert, Investigation } from '../types/soc';

interface DashboardPageProps {
  dashboardState: ReturnType<typeof useSocDashboard>;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ dashboardState }) => {
  const {
    kpis,
    investigations,
    alerts,
    threatOverview,
    trustMetrics,
    setIsNewModalOpen,
    handleViewInvestigation,
    statusFilter,
    setStatusFilter,
    searchQuery,
    setSearchQuery,
  } = dashboardState;

  // When user clicks "Investigate" from an alert in the alerts section
  const handleInvestigateAlert = (_alert: SecurityAlert) => {
    setIsNewModalOpen(true);
  };

  // When user selects an investigation from the trust overview list
  const handleSelectInvestigationById = (id: string) => {
    handleViewInvestigation(id);
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* 0. Hero Philosophy Banner (Lines 495-501: "Investigate → Challenge → Prove → Audit") */}
      <section className="bg-gradient-to-r from-[#0F172A] via-[#090D16] to-[#0F172A] border border-slate-800/80 rounded-2xl p-6 shadow-xl relative overflow-hidden" aria-label="Core Philosophy & Posture">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col xl:flex-row xl:items-center justify-between gap-6">
          <div className="space-y-3">
            {/* 5 Core SOC Status Pillars: Security Posture, Active Investigations, Agent Activity, Evidence Coverage, Trust Score */}
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-mono font-bold text-cyan-400 bg-cyan-950/80 border border-cyan-800/60 px-2 py-0.5 rounded-full flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                SECURITY POSTURE: ELEVATED (88/100)
              </span>
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-2 py-0.5 rounded-full flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                AUDIT INTEGRITY: 100% VERIFIED
              </span>
              <span className="text-[11px] font-mono text-indigo-400 bg-indigo-950/60 border border-indigo-800/50 px-2 py-0.5 rounded-full flex items-center gap-1.5">
                <Bot className="w-3.5 h-3.5" />
                AGENT SWARM: 5 ACTIVE
              </span>
              <span className="text-[11px] font-mono text-amber-400 bg-amber-950/60 border border-amber-800/50 px-2 py-0.5 rounded-full flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5" />
                ACTIVE CASES: {kpis?.activeInvestigations ?? investigations.length}
              </span>
              <span className="text-[11px] font-mono text-teal-400 bg-teal-950/60 border border-teal-800/50 px-2 py-0.5 rounded-full flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5" />
                EVIDENCE COVERAGE: 95% CORROBORATED
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100 tracking-tight font-mono">
              Investigate <span className="text-cyan-400">→</span> Challenge <span className="text-amber-400">→</span> Prove <span className="text-emerald-400">→</span> Audit
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl leading-relaxed">
              Auditable cyber investigation platform powered by autonomous AI agent swarms. Every hypothesis is challenged by adversarial critics, corroborated against tamper-evident evidence, and sealed into immutable cryptographic ledgers.
            </p>
          </div>

          {/* Right Column: Prominent Circular Radial Trust Score Gauge & Quick Action Buttons */}
          <div className="flex flex-wrap items-center gap-4 shrink-0">
            <div className="flex items-center gap-3.5 p-3 rounded-xl bg-slate-900/80 border border-slate-800 shadow-inner">
              <TrustScoreCircularGauge
                score={kpis?.averageTrustScore ?? 88}
                size="sm"
                verdict="HIGH_TRUST"
              />
              <div className="space-y-0.5 font-mono">
                <div className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">System Trust Index</div>
                <div className="text-xs font-semibold text-slate-200">Autonomous Swarm Confidence</div>
                <div className="text-[10px] text-emerald-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  6-Factor Corroborated
                </div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row xl:flex-col gap-2 shrink-0">
              <button
                onClick={() => setIsNewModalOpen(true)}
                className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs font-mono transition-all flex items-center justify-center gap-1.5 shadow-md shadow-cyan-950/40"
              >
                <Plus className="w-3.5 h-3.5" />
                Start Investigation
              </button>
              <button
                onClick={() => {
                  if (investigations.length > 0) handleViewInvestigation(investigations[0]);
                }}
                className="px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-700 hover:border-cyan-500/60 text-slate-200 text-xs font-mono transition-colors flex items-center justify-center gap-1.5"
              >
                <Play className="w-3.5 h-3.5 text-cyan-400" />
                Active Case (INV-001)
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 0.5. Interactive Multi-Agent Demo Action Orchestrator (Spec Lines 411-428) */}
      <section aria-label="Interactive Multi-Agent Demo Pipeline">
        <InteractiveDemoBar showToast={dashboardState.showToast} />
      </section>

      {/* 1. KPI Cards */}
      <section aria-label="Key Performance Indicators">
        <KpiCards kpis={kpis} />
      </section>

      {/* 2. Middle Row: Threat Overview & Trust Overview */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6" aria-label="Overview Analytics">
        {/* Threat Overview Chart (7 Cols on LG) */}
        <div className="lg:col-span-7">
          <ThreatOverviewChart data={threatOverview} />
        </div>

        {/* Evidence Trust Overview (5 Cols on LG) */}
        <div className="lg:col-span-5">
          <TrustOverviewCard
            metrics={trustMetrics}
            onSelectInvestigation={handleSelectInvestigationById}
          />
        </div>
      </section>

      {/* 2.5. Demonstration Scenarios (Module 3H True Positive & Module 3I Trap Scenario) */}
      <section aria-label="True Positive Scenario">
        <TruePositiveScenarioCard />
      </section>

      <section aria-label="Trap Scenario">
        <TrapScenarioCard />
      </section>

      {/* 2.6. Module 3Q: Autonomous Multi-Agent Activity Stream */}
      <section aria-label="Autonomous Multi-Agent Activity">
        <LiveAgentActivityPanel onSelectInvestigation={handleSelectInvestigationById} />
      </section>

      {/* 3. Active Investigations Section */}
      <section aria-label="Active Investigations Table">
        <InvestigationsTable
          investigations={investigations}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          onViewInvestigation={(inv: Investigation) => handleViewInvestigation(inv)}
          onOpenNewModal={() => setIsNewModalOpen(true)}
        />
      </section>

      {/* 4. Security Alerts Section */}
      <section aria-label="Security Alerts Stream">
        <AlertsSection
          alerts={alerts}
          onInvestigateAlert={handleInvestigateAlert}
        />
      </section>
    </div>
  );
};
