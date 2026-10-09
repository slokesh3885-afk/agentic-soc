from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class IncidentDossierModel(Base):
    """
    SQLAlchemy model for Incident Cases Dossier & MITRE ATT&CK Mapping (Module 3M).
    Aggregates multi-agent investigative cases into complete forensic dossiers mapped
    to the MITRE ATT&CK Enterprise Matrix, tracking an unbroken chain of forensic custody.
    """
    __tablename__ = "incident_dossiers"

    id = Column(String, primary_key=True, index=True)  # e.g., "DOS-001", "DOS-002"
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, unique=True, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="High")  # "Critical", "High", "Medium", "Low"
    status = Column(String, nullable=False, default="Open")    # "Open", "Under Review", "Contained", "Closed"
    threat_actor_attribution = Column(String, nullable=True)   # Evaluated against Critic Agent verification
    primary_tactic = Column(String, nullable=False, default="Execution") # e.g. "Execution", "Persistence"
    mitre_techniques_json = Column(Text, nullable=False, default="[]")   # Array of MitreTechniqueMapping
    custody_chain_json = Column(Text, nullable=False, default="[]")      # Array of ForensicCustodyEvent
    summary = Column(Text, nullable=False, default="")
    recommendations_json = Column(Text, nullable=False, default="[]")    # Array of recommended actions
    created_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    updated_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    # Relationship to InvestigationModel
    investigation = relationship("InvestigationModel", back_populates="dossier")

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "threat_actor_attribution": self.threat_actor_attribution,
            "primary_tactic": self.primary_tactic,
            "mitre_techniques": json.loads(self.mitre_techniques_json) if self.mitre_techniques_json else [],
            "custody_chain": json.loads(self.custody_chain_json) if self.custody_chain_json else [],
            "summary": self.summary,
            "recommendations": json.loads(self.recommendations_json) if self.recommendations_json else [],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
