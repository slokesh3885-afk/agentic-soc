import { useState, useEffect, useCallback } from 'react';
import type {
  DashboardKpi,
  Investigation,
  SecurityAlert,
  ThreatOverviewPoint,
  EvidenceTrustMetric,
  NewInvestigationPayload,
  InvestigationStatus,
} from '../types/soc';
import { socApi } from '../lib/api';

export function useSocDashboard() {
  const [kpis, setKpis] = useState<DashboardKpi | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [threatOverview, setThreatOverview] = useState<ThreatOverviewPoint[]>([]);
  const [trustMetrics, setTrustMetrics] = useState<EvidenceTrustMetric[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(true);
  const [connectionMessage, setConnectionMessage] = useState<string>('Connecting to FastAPI backend...');

  // UI state
  const [isNewModalOpen, setIsNewModalOpen] = useState(false);
  const [selectedInvestigation, setSelectedInvestigation] = useState<Investigation | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Handle Toast popup
  const showToast = useCallback((message: string) => {
    setToastMessage(message);
    setTimeout(() => {
      setToastMessage((current) => (current === message ? null : current));
    }, 4500);
  }, []);

  const closeToast = useCallback(() => {
    setToastMessage(null);
  }, []);

  // Load initial data from FastAPI backend
  const loadData = useCallback(async () => {
    try {
      setIsLoading(true);

      // Check backend health
      const health = await socApi.checkHealth();
      setIsBackendConnected(health.isOnline);
      setConnectionMessage(health.message);

      const [kpiData, invData, alertsData, threatData, trustData] = await Promise.all([
        socApi.getDashboardKpis(),
        socApi.getInvestigations(),
        socApi.getAlerts(),
        socApi.getThreatOverview(),
        socApi.getEvidenceTrustMetrics(),
      ]);

      setKpis(kpiData);
      setInvestigations(invData);
      setAlerts(alertsData);
      setThreatOverview(threatData);
      setTrustMetrics(trustData);
    } catch (err: any) {
      console.error('Failed to load SOC dashboard data:', err);
      setIsBackendConnected(false);
      setConnectionMessage('FastAPI backend connection failure. Using offline cached state.');
      showToast('Backend unavailable. Showing local telemetry cache.');
    } finally {
      setIsLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle opening investigation details by fetching fresh state from FastAPI backend
  const handleViewInvestigation = useCallback(
    async (invOrId: Investigation | string) => {
      const id = typeof invOrId === 'string' ? invOrId : invOrId.id;
      // Pre-select if we already have an object to ensure immediate responsiveness
      if (typeof invOrId !== 'string') {
        setSelectedInvestigation(invOrId);
      }

      try {
        const freshInvestigation = await socApi.getInvestigation(id);
        setSelectedInvestigation(freshInvestigation);
      } catch (err: any) {
        console.warn(`Could not refresh investigation ${id} from backend:`, err);
        // If we only had string ID and failed to fetch, alert user
        if (typeof invOrId === 'string') {
          showToast(`Failed to load investigation details for ${id}.`);
        }
      }
    },
    [showToast]
  );

  // Handle new investigation creation (POST to FastAPI -> SQLite)
  const handleCreateInvestigation = useCallback(
    async (payload: NewInvestigationPayload) => {
      try {
        const created = await socApi.createInvestigation(payload);

        // Prepend created investigation to local state immediately
        setInvestigations((prev) => [created, ...prev.filter((i) => i.id !== created.id)]);

        // Refresh KPIs from backend
        const updatedKpis = await socApi.getDashboardKpis();
        setKpis(updatedKpis);

        // Also update trustMetrics
        setTrustMetrics((prev) => [
          {
            investigationId: created.id,
            alertTitle: created.alert,
            score: created.evidenceTrustScore,
            host: created.host,
            verifiedArtifactsCount: created.evidenceCount,
            totalArtifactsCount: Math.max(created.evidenceCount, 3),
            primaryCorroborator: 'Initial SIEM Alert Corroboration',
            status: created.status,
          },
          ...prev,
        ]);

        // Close modal
        setIsNewModalOpen(false);

        // Show specified success toast: "Investigation created successfully."
        showToast('Investigation created successfully.');
        setIsBackendConnected(true);
        return created;
      } catch (err: any) {
        console.error('Failed to create investigation:', err);
        showToast(`Error creating investigation: ${err.message || 'Backend rejected request'}`);
        throw err;
      }
    },
    [showToast]
  );

  // Filtered investigations based on status tab and search text
  const filteredInvestigations = investigations.filter((inv) => {
    const matchesStatus =
      statusFilter === 'All' || inv.status === (statusFilter as InvestigationStatus);
    const query = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !query ||
      inv.id.toLowerCase().includes(query) ||
      inv.alert.toLowerCase().includes(query) ||
      inv.host.toLowerCase().includes(query) ||
      inv.severity.toLowerCase().includes(query);

    return matchesStatus && matchesSearch;
  });

  return {
    kpis,
    investigations: filteredInvestigations,
    allInvestigations: investigations,
    alerts,
    threatOverview,
    trustMetrics,
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
    refreshData: loadData,
  };
}
