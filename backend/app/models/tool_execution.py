from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ToolExecutionModel(Base):
    """
    SQLAlchemy model for persistent Tool Execution Audit Log.
    Tracks every allow-listed security tool call, input parameters,
    resulting structured output, and bound Evidence ID for auditability.
    """
    __tablename__ = "tool_executions"

    id = Column(String, primary_key=True, index=True)  # e.g., "EXEC-001"
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, index=True)
    tool_name = Column(String, nullable=False, index=True)
    input = Column(Text, nullable=False)  # JSON-encoded input parameters
    output = Column(Text, nullable=False)  # JSON-encoded structured output
    timestamp = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    success = Column(Boolean, nullable=False, default=True)
    evidence_id = Column(String, ForeignKey("evidence.id"), nullable=True, index=True)
    error = Column(Text, nullable=True)

    # Relationships
    investigation = relationship("InvestigationModel", back_populates="tool_executions")
    evidence = relationship("EvidenceModel")
