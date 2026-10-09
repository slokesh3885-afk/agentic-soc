/**
 * Agentic SOC — Canonical Reusable Component Library (Module 3Y)
 * Mandated by prompt_d075_full.txt (lines 467–480 & lines 347–363)
 *
 * Exports the 12 canonical enterprise SOC components and shared UI primitives.
 */

// 1. AgentCard
export { AgentCard } from './AgentCard';
export type { AgentCardProps, AgentCardData } from './AgentCard';

// 2. EvidenceTable
export { EvidenceTable } from './EvidenceTable';
export type { EvidenceTableProps } from './EvidenceTable';

// 3. ClaimCard
export { ClaimCard } from './ClaimCard';
export type { ClaimCardProps, ClaimData } from './ClaimCard';

// 4. Timeline
export { Timeline } from './Timeline';
export type { TimelineProps, TimelineItem } from './Timeline';

// 5. TrustScore & Radial Progress Visualization
export { TrustScore, TrustScoreCircularGauge, deriveSixBreakdownFactors } from './TrustScore';
export type { TrustScoreProps, TrustScoreBreakdown } from './TrustScore';

// 6. AlertCard
export { AlertCard } from './AlertCard';
export type { AlertCardProps, AlertCardData } from './AlertCard';

// 7. AuditLog
export { AuditLog } from './AuditLog';
export type { AuditLogProps, AuditLogItem } from './AuditLog';

// 8. ApprovalCard
export { ApprovalCard } from './ApprovalCard';
export type { ApprovalCardProps, ApprovalCardData } from './ApprovalCard';

// 9. InvestigationHeader
export { InvestigationHeader } from './InvestigationHeader';
export type { InvestigationHeaderProps, InvestigationHeaderData } from './InvestigationHeader';

// 10. StatusBadge
export { StatusBadge } from './StatusBadge';
export type { StatusBadgeProps, StatusBadgeVariant } from './StatusBadge';

// 11. JsonViewer (Canonical 14-Field Audited Object Inspector)
export { JsonViewer } from './JsonViewer';

// 12. ChartCard
export { ChartCard } from './ChartCard';
export type { ChartCardProps } from './ChartCard';

// Primitives & Legacy Helpers
export { Badge } from './Badge';
export type { BadgeProps } from './Badge';
export { Button } from './Button';
export type { ButtonProps } from './Button';
export { Toast } from './Toast';
export { TrustScoreBar, TrustScoreLegend } from './TrustScoreBar';
