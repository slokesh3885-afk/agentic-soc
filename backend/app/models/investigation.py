from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text
from sqlalchemy.orm import relationship
from app.database import Base


class InvestigationModel(Base):
    """SQLAlchemy model for persistent SOC investigations."""
    __tablename__ = "investigations"

    id = Column(String, primary_key=True, index=True)  # e.g., "INV-001"
    alert_name = Column(String, nullable=False, index=True)
    target_host = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False)  # "Critical", "High", "Medium", "Low"
    event_timestamp = Column(String, nullable=False)
    description = Column(Text, nullable=True, default="")
    status = Column(String, nullable=False, default="Investigating")
    evidence_count = Column(Integer, nullable=False, default=0)
    trust_score = Column(Integer, nullable=False, default=90)
    created_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    assigned_agent = Column(String, nullable=True, default="Host Triage Agent")
    mitre_technique = Column(String, nullable=True, default="")
    evidence_corroboration = Column(Text, nullable=True, default="[]")

    # Relationship to EvidenceModel items
    evidence_items = relationship("EvidenceModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to ToolExecutionModel items
    tool_executions = relationship("ToolExecutionModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to InvestigationPlanModel items
    plans = relationship("InvestigationPlanModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to CriticReviewModel items
    critic_reviews = relationship("CriticReviewModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to AuditedCaseModel items
    audited_cases = relationship("AuditedCaseModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to ApprovalRequestModel items (Module 3J)
    approval_requests = relationship("ApprovalRequestModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to AuditEntryModel items (Module 3L)
    audit_entries = relationship("AuditEntryModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to IncidentDossierModel (Module 3M)
    dossier = relationship("IncidentDossierModel", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    # Relationship to ContainmentExecutionModel (Module 3N)
    containment_executions = relationship("ContainmentExecutionModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to ReplaySessionModel (Module 3O)
    replay_sessions = relationship("ReplaySessionModel", back_populates="investigation", cascade="all, delete-orphan")
    # Relationship to IncidentReportModel (Module 3P)
    reports = relationship("IncidentReportModel", back_populates="investigation", cascade="all, delete-orphan")

