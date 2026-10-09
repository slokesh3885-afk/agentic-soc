"""
Agent and Agent Activity Models (Module 3Q)
Agentic SOC — Auditable AI Security Operations Center

Defines SQLAlchemy ORM models for:
- AgentModel: Persistent state, execution time, task, action counts, and evidence counts for all 5 core SOC agents.
- AgentActivityModel: Chronological immutable log of actions performed by agents during investigations.
"""

from sqlalchemy import Column, String, Integer, Text, DateTime
from datetime import datetime, timezone
from app.database import Base


class AgentModel(Base):
    """
    Represents one of the 5 core SOC agents:
    1. Planner Agent
    2. Tool Agent
    3. Analyst Agent
    4. Critic / Red-Team Agent
    5. Auditor Agent
    """
    __tablename__ = "soc_agents"

    id = Column(String, primary_key=True, index=True)  # e.g., 'agent-planner', 'agent-tool', 'agent-analyst', 'agent-critic', 'agent-auditor'
    name = Column(String, nullable=False, unique=True) # e.g., 'Planner Agent'
    role = Column(String, nullable=False)              # e.g., 'Investigation Decomposition & Tool Planning'
    status = Column(String, nullable=False, default="IDLE") # IDLE, RUNNING, COMPLETED, DEGRADED
    current_task = Column(String, nullable=False, default="Awaiting task assignment")
    execution_time_ms = Column(Integer, nullable=False, default=0)
    actions_count = Column(Integer, nullable=False, default=0)
    evidence_generated = Column(Integer, nullable=False, default=0)
    capabilities_json = Column(Text, nullable=False, default="[]")
    last_active_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))


class AgentActivityModel(Base):
    """
    Represents an auditable event emitted by an agent.
    e.g.:
    [22:04:12] Planner Agent created investigation plan
    [22:04:15] Tool Agent queried authentication logs
    [22:04:21] Analyst Agent generated preliminary hypothesis
    """
    __tablename__ = "agent_activities"

    id = Column(String, primary_key=True, index=True) # ACT-001, ACT-002, ...
    investigation_id = Column(String, nullable=True, index=True) # e.g., 'INV-001'
    agent_id = Column(String, nullable=False, index=True)        # 'agent-analyst'
    agent_name = Column(String, nullable=False)                  # 'Analyst Agent'
    action = Column(String, nullable=False)                      # 'generated preliminary hypothesis'
    details = Column(Text, nullable=False, default="")           # Extended explanation / outcome
    evidence_ids_json = Column(Text, nullable=False, default="[]") # ['E-001', 'E-003']
    timestamp = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).strftime("%H:%M:%S"))
    full_datetime = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
