from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class AuditEntryModel(Base):
    """
    SQLAlchemy model for persistent Cryptographic Immutable Audit Trail (Module 3L).
    Implements a tamper-evident, append-only SHA-256 hash-chained ledger.
    Every entry references the previous block's SHA-256 hash, forming an unbroken cryptographic chain.
    """
    __tablename__ = "audit_ledger"

    id = Column(String, primary_key=True, index=True)  # e.g., "AUD-0000", "AUD-0001"
    sequence = Column(Integer, nullable=False, unique=True, index=True)  # 0 for Genesis, 1, 2, ...
    timestamp = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    event_type = Column(String, nullable=False, index=True)  # e.g., "GENESIS_BLOCK", "EVIDENCE_SEALED", "INVESTIGATION_SEALED"
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=True, index=True)
    actor = Column(String, nullable=False, default="System Auditor")
    payload_summary = Column(String, nullable=False)
    payload_hash = Column(String, nullable=False)  # SHA-256 of canonical event payload
    prev_hash = Column(String, nullable=False)     # SHA-256 of previous block (64 zeros for Genesis)
    entry_hash = Column(String, nullable=False, unique=True, index=True)  # SHA-256 of block header
    signature = Column(String, nullable=False)    # Cryptographic digital seal (SIG-VERIFIED:...)
    metadata_json = Column(Text, nullable=True, default="{}")

    # Relationship to InvestigationModel (optional linkage)
    investigation = relationship("InvestigationModel", back_populates="audit_entries")

    def to_dict(self):
        return {
            "id": self.id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "investigation_id": self.investigation_id,
            "actor": self.actor,
            "payload_summary": self.payload_summary,
            "payload_hash": self.payload_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "metadata_json": self.metadata_json,
        }
