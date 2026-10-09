from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Boolean, Float, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ApprovalRequestModel(Base):
    """
    SQLAlchemy model for persistent Human-in-the-Loop (HITL) Approval Requests (Module 3J).
    Serves as the deterministic safety gate for high-impact containment, case closure,
    and remediation actions proposed by autonomous agents.
    """
    __tablename__ = "approval_requests"

    id = Column(String, primary_key=True, index=True)  # e.g., "APP-001"
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, index=True)
    case_id = Column(String, nullable=True, index=True)  # e.g., "CASE-087"
    action_type = Column(String, nullable=False)  # "CASE_CLOSURE", "CONTAINMENT_ISOLATE_HOST", "CONTAINMENT_BLOCK_IP", "REMEDIAL_ACTION"
    recommended_action = Column(Text, nullable=False)
    risk_level = Column(String, nullable=False, default="MEDIUM")  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    trust_score = Column(Float, nullable=False, default=100.0)
    trust_verdict = Column(String, nullable=False, default="HIGH_TRUST")
    status = Column(String, nullable=False, default="PENDING")  # "PENDING", "APPROVED", "REJECTED", "CANCELLED"
    requested_by = Column(String, nullable=False, default="Auditor Agent")
    requested_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    reviewer = Column(String, nullable=True)
    decision_notes = Column(Text, nullable=True)
    decision_at = Column(String, nullable=True)
    requires_override = Column(Boolean, nullable=False, default=False)
    override_justification = Column(Text, nullable=True)

    # Relationship to InvestigationModel
    investigation = relationship("InvestigationModel", back_populates="approval_requests")
