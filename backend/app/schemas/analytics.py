"""
Module 3V: Overview Dashboard Analytics, Multi-Chart Engine & Security Posture Schemas
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AlertsOverTimePoint(BaseModel):
    """Data point for Alerts Over Time area chart."""
    timestamp: str = Field(..., description="Time label (e.g. 10:00, 12:00, 14:00)")
    alerts: int = Field(..., ge=0, description="Total ingested alerts")
    confirmed_threats: int = Field(..., ge=0, description="Confirmed malicious incidents")
    inconclusive: int = Field(..., ge=0, description="Inconclusive / false positive cases")


class InvestigationOutcomeDistribution(BaseModel):
    """Breakdown of investigation outcomes across historical cases."""
    outcome: str = Field(..., description="Outcome category (Confirmed Malicious, False Positive, etc.)")
    count: int = Field(..., ge=0, description="Number of investigations")
    percentage: float = Field(..., ge=0.0, le=100.0, description="Percentage of total")
    color: str = Field(..., description="Hex or Tailwind color code")


class EvidenceSourceDistribution(BaseModel):
    """Distribution of evidence artifacts by source telemetry engine."""
    source_type: str = Field(..., description="Evidence source type (SIEM_LOG, EDR_EVENT, etc.)")
    count: int = Field(..., ge=0, description="Total verified artifacts")
    percentage: float = Field(..., ge=0.0, le=100.0, description="Percentage of total evidence")
    reliability_avg: float = Field(..., ge=0.0, le=1.0, description="Average reliability metric")


class TrustScoreHistoryPoint(BaseModel):
    """Historical progression of investigation trust scores."""
    case_id: str = Field(..., description="Investigation ID or timestamp")
    label: str = Field(..., description="Display label (e.g. Case #12, Case #13)")
    trust_score: int = Field(..., ge=0, le=100, description="Explainable trust score (0-100)")
    coverage_score: int = Field(..., ge=0, le=100, description="Evidence coverage component")
    quality_score: int = Field(..., ge=0, le=100, description="Evidence quality component")
    benchmark_target: int = Field(85, description="Enterprise baseline threshold")


class PostureSummary(BaseModel):
    """High-level enterprise SOC security posture and operational metrics."""
    posture_status: str = Field("ELEVATED", description="Posture: SECURE, ELEVATED, HIGH_RISK, UNDER_ATTACK")
    posture_score: int = Field(88, ge=0, le=100, description="0-100 composite posture index")
    active_investigations: int = Field(..., ge=0)
    high_severity_cases: int = Field(..., ge=0)
    evidence_collected: int = Field(..., ge=0)
    cases_awaiting_approval: int = Field(..., ge=0)
    average_trust_score: float = Field(..., ge=0.0, le=100.0)
    evidence_coverage_pct: float = Field(..., ge=0.0, le=100.0)
    audit_integrity_status: str = Field("100% VERIFIED", description="Merkle hash-chain integrity")
    active_threats_blocked: int = Field(..., ge=0)
    philosophy: str = Field("Investigate → Challenge → Prove → Audit")
    updated_at: str = Field(...)


class OverviewAnalyticsResponse(BaseModel):
    """Complete aggregated overview analytics payload for the SOC dashboard."""
    posture: PostureSummary
    alerts_over_time: List[AlertsOverTimePoint]
    investigation_outcomes: List[InvestigationOutcomeDistribution]
    evidence_sources: List[EvidenceSourceDistribution]
    trust_score_history: List[TrustScoreHistoryPoint]
    generated_at: str
