"""
Module 3U: Enterprise SOC System Settings, Universal Omnibar Search & Notification Schemas
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class TrustScoreWeights(BaseModel):
    """Configurable weights for the explainable Trust Score algorithm."""
    evidence_coverage: float = Field(0.35, ge=0.0, le=1.0)
    evidence_quality: float = Field(0.25, ge=0.0, le=1.0)
    contradiction_handling: float = Field(0.20, ge=0.0, le=1.0)
    attribution_support: float = Field(0.10, ge=0.0, le=1.0)
    replay_consistency: float = Field(0.10, ge=0.0, le=1.0)


class SocSystemSettings(BaseModel):
    """Active configuration for the Agentic SOC platform."""
    platform_name: str = Field("Agentic SOC", description="Product title")
    tagline: str = Field("Investigate → Challenge → Prove → Audit", description="Core platform philosophy")
    environment: str = Field("production-ready-prototype", description="Active runtime tier")
    backend_version: str = Field("0.17.0", description="Backend service semantic version")
    database_type: str = Field("SQLite (Persistent)", description="Underlying database engine")
    database_path: str = Field("backend/agentic_soc.db", description="Database storage path")
    tool_registry_enforcement: bool = Field(True, description="Strict allow-list validation for tool executions")
    max_tool_execution_timeout_sec: int = Field(120, ge=5, le=600, description="Tool execution timeout in seconds")
    allowlisted_tools_count: int = Field(6, description="Total allow-listed tools in registry")
    attribution_policy_strictness: str = Field("STRICT", description="Attribution guard policy: STRICT, MEDIUM, ADVISORY")
    min_attribution_evidence_count: int = Field(3, ge=1, le=10, description="Minimum independent corroborations required for threat actor assertion")
    trust_score_weights: TrustScoreWeights = Field(default_factory=TrustScoreWeights, description="Trust score weight factors")
    websocket_telemetry_active: bool = Field(True, description="Real-time WebSocket streaming status")
    merkle_sealing_enabled: bool = Field(True, description="Cryptographic SHA-256 Merkle root sealing active")
    updated_at: str = Field(..., description="ISO 8601 timestamp of last settings update")


class SocSystemSettingsUpdate(BaseModel):
    """Payload to update SOC system configuration."""
    attribution_policy_strictness: Optional[str] = Field(None, description="STRICT, MEDIUM, ADVISORY")
    min_attribution_evidence_count: Optional[int] = Field(None, ge=1, le=10)
    max_tool_execution_timeout_sec: Optional[int] = Field(None, ge=5, le=600)
    tool_registry_enforcement: Optional[bool] = None
    websocket_telemetry_active: Optional[bool] = None
    merkle_sealing_enabled: Optional[bool] = None
    trust_score_weights: Optional[TrustScoreWeights] = None


class SearchResultItem(BaseModel):
    """Individual item discovered during universal omnibar search."""
    id: str = Field(..., description="Entity identifier (e.g. INV-001, EV-002, ALT-9042)")
    category: str = Field(..., description="Category: investigations, alerts, evidence, agents, audit_trail, cases")
    title: str = Field(..., description="Display title")
    description: str = Field(..., description="Context summary / snippet")
    severity_or_status: Optional[str] = Field(None, description="Severity badge or status")
    timestamp: Optional[str] = Field(None, description="Associated timestamp")
    route: str = Field(..., description="Navigation route or target ID")


class UniversalSearchResponse(BaseModel):
    """Aggregated universal omnibar search results across all SOC modules."""
    query: str = Field(..., description="Search query string")
    total_matches: int = Field(..., description="Total items found")
    categories: Dict[str, int] = Field(default_factory=dict, description="Counts by category")
    results: List[SearchResultItem] = Field(default_factory=list, description="Ordered search results")
    searched_at: str = Field(..., description="ISO 8601 search timestamp")


class SocNotificationItem(BaseModel):
    """Individual notification in the live SOC notification center."""
    id: str = Field(..., description="Unique notification ID (e.g. NOTIF-001)")
    title: str = Field(..., description="Notification headline")
    message: str = Field(..., description="Detailed message")
    severity: str = Field(..., description="critical, warning, info, success")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    read: bool = Field(False, description="Read/unread flag")
    category: str = Field(..., description="ALERT, ATTRIBUTION_BLOCKED, CONTRADICTION, APPROVAL_REQUIRED, AUDIT_SEALED")
    reference_id: Optional[str] = Field(None, description="Linked entity ID (e.g. INV-001)")


class NotificationsResponse(BaseModel):
    """Container for active notifications feed."""
    total_notifications: int = Field(..., description="Total notifications")
    unread_count: int = Field(..., description="Unread notification count")
    notifications: List[SocNotificationItem] = Field(default_factory=list, description="Ordered notifications")
