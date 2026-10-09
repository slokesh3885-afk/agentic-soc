"""
Pydantic Schemas for Forensic Timeline Replay & Investigation Reproducibility Engine (Module 3O).
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    """Normalized chronological step within an investigation's forensic timeline."""
    step_index: int = Field(..., description="Monotonically increasing chronological step index starting at 1")
    event_type: str = Field(..., description="Categorical event type (e.g. ALERT_RECEIVED, PLAN_FORMULATED, TOOL_EXECUTED, EVIDENCE_CAPTURED, CRITIC_REVIEWED, CASE_AUDITED, TRUST_SCORED, APPROVAL_REQUESTED, APPROVAL_DECIDED, CONTAINMENT_DISPATCHED, AUDIT_SEALED)")
    title: str = Field(..., description="Human-readable milestone title")
    description: str = Field(..., description="Technical summary of what occurred in this step")
    timestamp: str = Field(..., description="ISO 8601 or formatted UTC timestamp")
    actor: str = Field(..., description="Agent, tool, or human actor executing the step")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary step telemetry attributes")
    artifact_ref: Optional[str] = Field(None, description="Primary artifact identifier reference (e.g. E-001, EXEC-001, AUD-0001, CONT-001)")
    state_snapshot: Optional[Dict[str, Any]] = Field(None, description="Cumulative investigation state at this exact milestone")


class ReplayTriggerPayload(BaseModel):
    """Payload to request deterministic re-execution of an existing investigation."""
    investigation_id: str = Field(..., description="Investigation ID to replay (e.g. INV-001)")
    notes: Optional[str] = Field(None, description="Auditor rationale or replay trigger context")
    strict_verification: bool = Field(True, description="Enforce strict 100% deterministic assertion on verdict and claims")


class ReplayComparisonMatrix(BaseModel):
    """Comparison matrix between historical investigation and replayed execution."""
    verdict_match: bool = Field(..., description="Whether original and replayed verdicts are identical")
    original_verdict: str = Field(..., description="Historical adjudication verdict")
    replayed_verdict: str = Field(..., description="Verdict recomputed during replay")
    trust_score_delta: float = Field(0.0, description="Absolute difference between original and replayed trust scores")
    original_trust_score: float = Field(..., description="Original trust score")
    replayed_trust_score: float = Field(..., description="Replayed trust score")
    claims_match_rate: float = Field(100.0, description="Percentage of claims matching replayed evidence backing")
    evidence_integrity_verified: bool = Field(True, description="Whether all evidence SHA-256 hashes matched snapshot")
    divergence_count: int = Field(0, description="Number of detected analytical divergences (0 for 100% deterministic)")
    divergence_notes: List[str] = Field(default_factory=list, description="Descriptions of any detected divergences")


class ReplaySessionResponse(BaseModel):
    """Detailed response schema for an investigation replay session."""
    id: str = Field(..., description="Replay session ID (e.g. RPL-001)")
    investigation_id: str = Field(..., description="Linked investigation ID")
    status: str = Field(..., description="Replay status (COMPLETED, RUNNING, FAILED)")
    original_verdict: str = Field(..., description="Original case verdict")
    replayed_verdict: str = Field(..., description="Replayed case verdict")
    verdict_match: bool = Field(..., description="Verdict match indicator")
    consistency_score: float = Field(..., description="Overall reproducibility consistency score (0.0 - 100.0%)")
    claims_match_rate: float = Field(..., description="Claims corroboration match rate (0.0 - 100.0%)")
    original_trust_score: float = Field(..., description="Original trust score")
    replayed_trust_score: float = Field(..., description="Replayed trust score")
    evidence_snapshot_hash: str = Field(..., description="SHA-256 fingerprint of evidence snapshot used for replay")
    total_steps: int = Field(..., description="Total chronological timeline steps reconstructed")
    replay_duration_ms: int = Field(..., description="Deterministic simulation execution time in milliseconds")
    executed_at: str = Field(..., description="Timestamp replay was triggered")
    replayed_by: str = Field(..., description="Operator or automated engine that triggered replay")
    audit_entry_id: Optional[str] = Field(None, description="Module 3L audit ledger block ID (e.g. AUD-0030)")
    comparison: ReplayComparisonMatrix = Field(..., description="Detailed divergence & comparison matrix")
    timeline: List[TimelineEvent] = Field(default_factory=list, description="Chronological step-by-step reconstructed timeline")


class ReplaySummaryResponse(BaseModel):
    """Operational summary of all forensic replay sessions in the SOC."""
    total_replays: int = Field(..., description="Total replays executed")
    average_consistency: float = Field(..., description="Mean consistency score across all replays")
    perfect_replays_count: int = Field(..., description="Number of replays with 100% consistency")
    divergent_replays_count: int = Field(..., description="Number of replays with detected divergences")
    investigations_replayed: int = Field(..., description="Count of unique investigations evaluated for reproducibility")
    by_verdict: Dict[str, int] = Field(default_factory=dict, description="Breakdown of replays by verdict outcome")
