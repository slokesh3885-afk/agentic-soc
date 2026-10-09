"""
Database Model for Forensic Replay & Investigation Reproducibility Engine (Module 3O).
Agentic SOC — Auditable AI Security Operations Center
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ReplaySessionModel(Base):
    """
    Persisted record of an investigation replay execution.
    Ensures 100% deterministic reproducibility verification of multi-agent conclusions.
    """
    __tablename__ = "replay_sessions"

    id = Column(String, primary_key=True, index=True)  # e.g., 'RPL-001'
    investigation_id = Column(String, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String, nullable=False, default="COMPLETED")  # COMPLETED, IN_PROGRESS, FAILED
    
    # Verdict comparison
    original_verdict = Column(String, nullable=False)
    replayed_verdict = Column(String, nullable=False)
    verdict_match = Column(Boolean, nullable=False, default=True)
    
    # Consistency metrics
    consistency_score = Column(Float, nullable=False, default=100.0)  # 0.0 to 100.0%
    claims_match_rate = Column(Float, nullable=False, default=100.0)  # 0.0 to 100.0%
    original_trust_score = Column(Float, nullable=False, default=0.0)
    replayed_trust_score = Column(Float, nullable=False, default=0.0)
    
    # Evidence snapshot cryptographic hash
    evidence_snapshot_hash = Column(String, nullable=False)  # SHA-256 of frozen evidence items
    
    # Detailed timeline and divergence tracking
    timeline_events_json = Column(Text, nullable=False)  # JSON array of unified TimelineEvent objects
    divergence_notes_json = Column(Text, nullable=True)  # JSON array of divergence explanations (if any)
    
    total_steps = Column(Integer, nullable=False, default=0)
    replay_duration_ms = Column(Integer, nullable=False, default=0)
    
    # Audit trail integration
    audit_entry_id = Column(String, nullable=True)  # Reference to Module 3L audit block (e.g. AUD-0030)
    
    executed_at = Column(String, nullable=False)  # ISO timestamp
    replayed_by = Column(String, nullable=False, default="Deterministic Replay Engine")

    # Relationship back to investigation
    investigation = relationship("InvestigationModel", back_populates="replay_sessions")
