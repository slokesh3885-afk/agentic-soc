from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class InvestigationPlanModel(Base):
    """
    SQLAlchemy model for persistent investigation plans created by the Planner Agent.
    Strictly documents proposed allow-listed tool execution steps without directly executing them.
    """
    __tablename__ = "investigation_plans"

    id = Column(String, primary_key=True, index=True)  # e.g., "PLAN-001"
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, index=True)
    alert = Column(Text, nullable=False)
    plan_steps = Column(Text, nullable=False)  # JSON-encoded array of PlanStep objects
    status = Column(String, nullable=False, default="PROPOSED")
    created_at = Column(
        String,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    # Relationship to InvestigationModel
    investigation = relationship("InvestigationModel", back_populates="plans")
