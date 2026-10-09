import { useState, useEffect } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { TopBar } from './components/layout/TopBar';
import { DashboardPage } from './pages/DashboardPage';
import { useSocDashboard } from './hooks/useSocDashboard';
import { InvestigationsTable } from './components/dashboard/InvestigationsTable';
import { AlertsSection } from './components/dashboard/AlertsSection';
import { NewInvestigationModal } from './components/modals/NewInvestigationModal';
import { InvestigationDetailModal } from './components/modals/InvestigationDetailModal';
import { UniversalOmnibarModal } from './components/modals/UniversalOmnibarModal';
import { SettingsControlPlaneView } from './components/settings/SettingsControlPlaneView';
import { Toast } from './components/ui/Toast';
import { useAlertsSocket } from './hooks/useAlertsSocket';
import { AuditTrailView } from './components/audit/AuditTrailView';
import { CasesDossierView } from './components/cases/CasesDossierView';
import { ReplayView } from './components/replay/ReplayView';
import { ReportsView } from './components/reports/ReportsView';
import { AgentsView } from './components/agents/AgentsView';
import { EvidenceControlPlaneView } from './components/evidence/EvidenceControlPlaneView';
import { CriticRedTeamView } from './components/critic/CriticRedTeamView';
import { OverviewAnalyticsView } from './components/analytics/OverviewAnalyticsView';

export function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isOmnibarOpen, setIsOmnibarOpen] = useState(false);
  const dashboardState = useSocDashboard();

  const { isConnected: isWsConnected, alerts: wsAlerts } = useAlertsSocket((event) => {
    if (event.event === 'ALERT_CREATED') {
      dashboardState.refreshData();
    }
  });

  const {
    kpis,
    investigations,
    alerts,
    isLoading,
    isBackendConnected,
    connectionMessage,
    isNewModalOpen,
    setIsNewModalOpen,
    selectedInvestigation,
    setSelectedInvestigation,
    handleViewInvestigation,
    statusFilter,
    setStatusFilter,
    searchQuery,
    setSearchQuery,
    toastMessage,
    showToast,
    closeToast,
    handleCreateInvestigation,
    refreshData,
  } = dashboardState;

  // Global Omnibar Keyboard Shortcut (Ctrl+K or /)
  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsOmnibarOpen(true);
      } else if (
        e.key === '/' &&
        document.activeElement?.tagName !== 'INPUT' &&
        document.activeElement?.tagName !== 'TEXTAREA'
      ) {
        e.preventDefault();
        setIsOmnibarOpen(true);
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#090D16] text-slate-100 font-sans">
      {/* Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        investigationCount={kpis?.activeInvestigations || 4}
        alertCount={kpis?.openAlerts || 19}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden min-w-0">
        {/* Top Bar */}
        <TopBar
          onRefresh={refreshData}
          isLoading={isLoading}
          isBackendConnected={isBackendConnected}
          connectionMessage={connectionMessage}
          isWebSocketConnected={isWsConnected}
          wsEventCount={wsAlerts.length}
          onSelectInvestigation={(id) => handleViewInvestigation(id)}
          onOpenOmnibar={() => setIsOmnibarOpen(true)}
        />

        {/* Dynamic Page Views */}
        <main className="flex-1 overflow-y-auto">
          {activeTab === 'dashboard' && (
            <DashboardPage dashboardState={dashboardState} />
          )}

          {activeTab === 'investigations' && (
            <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-slate-100 font-mono">
                    All SOC Investigations
                  </h2>
                  <p className="text-xs text-slate-400">
                    Comprehensive ledger of active, completed, and inconclusive investigative hypotheses
                  </p>
                </div>
              </div>
              <InvestigationsTable
                investigations={investigations}
                statusFilter={statusFilter}
                setStatusFilter={setStatusFilter}
                searchQuery={searchQuery}
                setSearchQuery={setSearchQuery}
                onViewInvestigation={(inv) => handleViewInvestigation(inv)}
                onOpenNewModal={() => setIsNewModalOpen(true)}
              />
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-slate-100 font-mono">
                    Security Alerts Ingestion Feed
                  </h2>
                  <p className="text-xs text-slate-400">
                    Normalized event telemetry streamed from multi-cloud and on-premise detection sensors
                  </p>
                </div>
              </div>
              <AlertsSection
                alerts={alerts}
                onInvestigateAlert={() => setIsNewModalOpen(true)}
              />
            </div>
          )}

          {activeTab === 'evidence' && (
            <EvidenceControlPlaneView onSelectInvestigation={(id) => handleViewInvestigation(id)} />
          )}

          {activeTab === 'agents' && (
            <AgentsView onSelectInvestigation={(id) => handleViewInvestigation(id)} />
          )}

          {activeTab === 'critic-redteam' && (
            <CriticRedTeamView onSelectInvestigation={(id) => handleViewInvestigation(id)} />
          )}

          {activeTab === 'cases' && (
            <CasesDossierView onSelectInvestigation={(id) => handleViewInvestigation(id)} />
          )}

          {activeTab === 'audit-trail' && (
            <AuditTrailView />
          )}

          {activeTab === 'replay' && (
            <ReplayView onSelectInvestigation={(id) => handleViewInvestigation(id)} />
          )}

          {activeTab === 'reports' && (
            <ReportsView onSelectInvestigation={(id) => handleViewInvestigation(id)} />
          )}

          {activeTab === 'analytics' && (
            <OverviewAnalyticsView onSelectInvestigation={(id) => handleViewInvestigation(id)} />
          )}

          {activeTab === 'settings' && (
            <SettingsControlPlaneView showToast={showToast} />
          )}
        </main>
      </div>

      {/* Global Modals */}
      <NewInvestigationModal
        isOpen={isNewModalOpen}
        onClose={() => setIsNewModalOpen(false)}
        onSubmit={handleCreateInvestigation}
      />

      <InvestigationDetailModal
        investigation={selectedInvestigation}
        onClose={() => setSelectedInvestigation(null)}
        onEvidenceCountUpdated={(newCount) => {
          if (selectedInvestigation) {
            setSelectedInvestigation({
              ...selectedInvestigation,
              evidenceCount: newCount,
              artifactCount: newCount,
            });
            refreshData();
          }
        }}
      />

      {/* Universal Omnibar Search Modal (Spec Line 58) */}
      <UniversalOmnibarModal
        isOpen={isOmnibarOpen}
        onClose={() => setIsOmnibarOpen(false)}
        onSelectInvestigation={(id) => handleViewInvestigation(id)}
        onNavigateTab={(tab) => setActiveTab(tab)}
      />

      <Toast message={toastMessage} onClose={closeToast} />
    </div>
  );
}

export default App;
