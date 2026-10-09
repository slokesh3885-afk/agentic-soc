"""
Human-in-the-Loop (HITL) Approval Schemas (Module 3J)
Agentic SOC — Auditable AI Security Operations Center

Defines schemas for human analyst safety gates:
- ApprovalRequest: Auditable approval record for containment, remediation, and case closure
- ApprovalDecisionPayload: Reviewer decision with notes and mandatory override justification
- ApprovalCreatePayload: Programmatic or analyst request creation
"""

from typing import List, Optional, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


ApprovalActionType = Literal[
    "CASE_CLOSURE",
    "CONTAINMENT_ISOLATE_HOST",
    "CONTAINMENT_BLOCK_IP",
    "REMEDIAL_ACTION",
    "ESCALATION_TIER2",
]

ApprovalStatus = Literal[
    "PENDING",
    "APPROVED",
    "REJECTED",
    "CANCELLED",
]

ApprovalRiskLevel = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


class ApprovalCreatePayload(BaseModel):
    """Payload to request human approval for a high-impact SOC action."""
    model_config = ConfigDict(extra="ignore")

    action_type: ApprovalActionType = Field(..., description="Type of proposed SOC action")
    recommended_action: str = Field(..., min_length=5, description="Clear description of the recommended action")
    risk_level: ApprovalRiskLevel = Field(default="MEDIUM", description="Risk assessment level")
    requested_by: str = Field(default="Auditor Agent", description="Agent or analyst requesting approval")
    case_id: Optional[str] = Field(default=None, description="Optional associated Audited Case ID")


class ApprovalDecisionPayload(BaseModel):
    """Payload submitted by human analyst to approve, reject, or cancel an action."""
    model_config = ConfigDict(extra="ignore")

    decision: Literal["APPROVED", "REJECTED", "CANCELLED"] = Field(..., description="Analyst decision")
    reviewer: str = Field(..., min_length=2, description="Analyst name or ID executing the decision")
    decision_notes: str = Field(..., min_length=5, description="Analyst rationale/justification for decision")
    override_justification: Optional[str] = Field(
        default=None,
        description="Mandatory justification when approving a case with Trust Score < 60 or contradictions",
    )


class ApprovalResponse(BaseModel):
    """Auditable Human Approval Request representation."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Approval ID (e.g. APP-001)")
    investigation_id: str = Field(..., description="Associated Investigation ID")
    case_id: Optional[str] = Field(default=None, description="Associated Case ID if audited")
    action_type: str = Field(..., description="Proposed action type")
    recommended_action: str = Field(..., description="Description of proposed action")
    risk_level: str = Field(..., description="Risk assessment level")
    trust_score: float = Field(..., description="Snapshot of Evidence Trust Score (0-100)")
    trust_verdict: str = Field(..., description="Trust verdict (HIGH_TRUST, LOW_TRUST, UNTRUSTED)")
    status: str = Field(..., description="Approval state (PENDING, APPROVED, REJECTED, CANCELLED)")
    requested_by: str = Field(..., description="Requester entity")
    requested_at: str = Field(..., description="Timestamp of request")
    reviewer: Optional[str] = Field(default=None, description="Reviewing analyst")
    decision_notes: Optional[str] = Field(default=None, description="Reviewer notes")
    decision_at: Optional[str] = Field(default=None, description="Timestamp of decision")
    requires_override: bool = Field(default=False, description="Flag indicating safety override requirement")
    override_justification: Optional[str] = Field(default=None, description="Recorded override rationale")

    # Frontend camelCase aliases
    investigationId: Optional[str] = None
    caseId: Optional[str] = None
    actionType: Optional[str] = None
    recommendedAction: Optional[str] = None
    riskLevel: Optional[str] = None
    trustScore: Optional[float] = None
    trustVerdict: Optional[str] = None
    requestedBy: Optional[str] = None
    requestedAt: Optional[str] = None
    decisionNotes: Optional[str] = None
    decisionAt: Optional[str] = None
    requiresOverride: Optional[bool] = None
    overrideJustification: Optional[str] = None

    @model_validator(mode="after")
    def populate_camel_case_aliases(self) -> "ApprovalResponse":
        self.investigationId = self.investigationId or self.investigation_id
        self.caseId = self.caseId or self.case_id
        self.actionType = self.actionType or self.action_type
        self.recommendedAction = self.recommendedAction or self.recommended_action
        self.riskLevel = self.riskLevel or self.risk_level
        self.trustScore = self.trustScore if self.trustScore is not None else self.trust_score
        self.trustVerdict = self.trustVerdict or self.trust_verdict
        self.requestedBy = self.requestedBy or self.requested_by
        self.requestedAt = self.requestedAt or self.requested_at
        self.decisionNotes = self.decisionNotes or self.decision_notes
        self.decisionAt = self.decisionAt or self.decision_at
        self.requiresOverride = self.requiresOverride if self.requiresOverride is not None else self.requires_override
        self.overrideJustification = self.overrideJustification or self.override_justification
        return self


class ApprovalListResponse(BaseModel):
    """Paginated or filtered list of approvals."""
    total: int = Field(..., ge=0)
    pending_count: int = Field(..., ge=0)
    approvals: List[ApprovalResponse] = Field(default_factory=list)

    pendingCount: Optional[int] = None

    @model_validator(mode="after")
    def populate_aliases(self) -> "ApprovalListResponse":
        self.pendingCount = self.pendingCount if self.pendingCount is not None else self.pending_count
        return self
