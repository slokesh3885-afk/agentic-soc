import json
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class CriticReviewModel(Base):
    """
    SQLAlchemy model for persisting Critic / Red-Team evaluation reviews.
    Records every challenge against investigator draft conclusions,
    storing objections, contradictions, overclaims, and claim evaluations.
    """
    __tablename__ = "critic_reviews"

    id = Column(String, primary_key=True, index=True)  # e.g., "CRITIC-001" or UUID
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, index=True)
    draft_conclusion = Column(Text, nullable=False)
    overall_status = Column(String, nullable=False)  # "PASS" or "REQUIRES_REVISION"
    claims_evaluation = Column(Text, nullable=False, default="[]")  # JSON-serialized list of evaluations
    objections = Column(Text, nullable=False, default="[]")  # JSON-serialized list of objections
    missing_evidence = Column(Text, nullable=False, default="[]")  # JSON-serialized list of missing evidence strings
    contradictions = Column(Text, nullable=False, default="[]")  # JSON-serialized list of contradictions
    overclaims = Column(Text, nullable=False, default="[]")  # JSON-serialized list of overclaims
    created_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    # Relationship to InvestigationModel
    investigation = relationship("InvestigationModel", back_populates="critic_reviews")

    def get_claims_evaluation(self):
        try:
            return json.loads(self.claims_evaluation)
        except Exception:
            return []

    def get_objections(self):
        try:
            return json.loads(self.objections)
        except Exception:
            return []

    def get_missing_evidence(self):
        try:
            return json.loads(self.missing_evidence)
        except Exception:
            return []

    def get_contradictions(self):
        try:
            return json.loads(self.contradictions)
        except Exception:
            return []

    def get_overclaims(self):
        try:
            return json.loads(self.overclaims)
        except Exception:
            return []
