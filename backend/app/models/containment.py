from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ContainmentExecutionModel(Base):
    """
    SQLAlchemy model for persistent Automated Containment & Remediation Playbooks (Module 3N).
    Tracks every allow-listed containment action, execution steps, target entities,
    cryptographic quarantine receipts, and rollback states.
    """
    __tablename__ = "containment_executions"

    id = Column(String, primary_key=True, index=True)  # e.g., "CONT-001"
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, index=True)
    approval_id = Column(String, nullable=True, index=True)  # e.g., "APP-001"
    playbook_id = Column(String, nullable=False, index=True)  # "PLAYBOOK-HOST-ISOLATION", "PLAYBOOK-NETWORK-BLOCK", etc.
    playbook_name = Column(String, nullable=False)
    target_type = Column(String, nullable=False)  # "HOST", "IP_ADDRESS", "DOMAIN", "PROCESS"
    target_identifier = Column(String, nullable=False, index=True)  # e.g., "DC-PROD-01.corp.internal"
    status = Column(String, nullable=False, default="CONTAINED")  # "DISPATCHED", "EXECUTING", "CONTAINED", "FAILED", "ROLLED_BACK"
    execution_steps_json = Column(Text, nullable=False, default="[]")  # JSON-serialized steps with artifact hashes
    dispatched_by = Column(String, nullable=False, default="sec_analyst_01")
    dispatched_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    completed_at = Column(String, nullable=True)
    rollback_enabled = Column(Boolean, nullable=False, default=True)
    rolled_back_at = Column(String, nullable=True)
    rollback_notes = Column(Text, nullable=True)
    audit_entry_id = Column(String, nullable=True)  # Link to Module 3L audit entry
    quarantine_receipt_hash = Column(String, nullable=False)  # SHA-256 of containment parameters

    # Relationship to InvestigationModel
    investigation = relationship("InvestigationModel", back_populates="containment_executions")
