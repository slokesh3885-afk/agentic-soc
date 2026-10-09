from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class EvidenceModel(Base):
    """SQLAlchemy model for the persistent, tamper-evident Evidence Engine."""
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, index=True)  # e.g., "E-001", "E-002"
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, index=True)
    evidence_type = Column(String, nullable=False)  # Validated against EvidenceType enum
    source = Column(String, nullable=False)  # e.g. "Mock SIEM", "Mock EDR"
    timestamp = Column(String, nullable=False)
    query = Column(Text, nullable=True, default="")
    raw_output = Column(Text, nullable=False)
    content_hash = Column(String, nullable=False)  # SHA-256 hex digest of raw_output
    status = Column(String, nullable=False, default="COLLECTED")
    created_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    # Relationship to InvestigationModel
    investigation = relationship("InvestigationModel", back_populates="evidence_items")
