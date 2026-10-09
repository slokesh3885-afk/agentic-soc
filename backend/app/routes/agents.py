"""
Multi-Agent Swarm Orchestration & Control Plane Router (Module 3Q)
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.agent import (
    AgentResponse,
    AgentActivityResponse,
    AgentSwarmSummary,
    AnalystRequestPayload,
    AnalystResponse,
    SwarmOrchestratePayload,
    SwarmOrchestrateResponse,
)
from app.services.agent_service import (
    get_all_agents,
    get_agent,
    get_agent_summary,
    get_agent_activities,
    orchestrate_investigation_swarm,
)
from app.services.analyst_service import run_analyst_agent

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get(
    "/summary",
    response_model=AgentSwarmSummary,
    status_code=status.HTTP_200_OK,
    summary="Get multi-agent swarm KPI summary and health metrics",
)
def fetch_agents_summary(
    db: Session = Depends(get_db),
):
    """Retrieves high-level swarm health, agent statuses, and aggregate execution statistics."""
    return get_agent_summary(db)


@router.get(
    "",
    response_model=List[AgentResponse],
    status_code=status.HTTP_200_OK,
    summary="List all 5 core SOC agents and their operational states",
)
def fetch_agents_list(
    db: Session = Depends(get_db),
):
    """
    Returns the complete registry of 5 core SOC agents:
    1. Planner Agent
    2. Tool Agent
    3. Analyst Agent
    4. Critic / Red-Team Agent
    5. Auditor Agent
    """
    return get_all_agents(db)


@router.get(
    "/activity",
    response_model=List[AgentActivityResponse],
    status_code=status.HTTP_200_OK,
    summary="List recent chronological multi-agent activity stream",
)
def fetch_agent_activities(
    limit: int = Query(50, ge=1, le=200, description="Maximum entries to return"),
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    db: Session = Depends(get_db),
):
    """
    Returns recent chronological auditable events emitted across the multi-agent swarm.
    e.g. [22:04:12] Planner Agent created investigation plan.
    """
    return get_agent_activities(db, limit=limit, investigation_id=investigation_id, agent_id=agent_id)


@router.get(
    "/{agent_id}",
    response_model=AgentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get operational state and telemetry for a specific agent",
)
def fetch_agent_by_id(
    agent_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves status, current task, latency, and capabilities for a single agent."""
    agent = get_agent(db, agent_id=agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found in registry",
        )
    return agent


@router.post(
    "/analyst/analyze",
    response_model=AnalystResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Analyst Agent reasoning on an investigation",
)
def execute_analyst_analysis(
    payload: AnalystRequestPayload,
    db: Session = Depends(get_db),
):
    """
    Executes the Analyst Agent reasoning layer:
    - Synthesizes preliminary hypotheses from alert context and gathered evidence
    - Formulates structured claims tied directly to evidence IDs
    - Maps observed behaviors to MITRE ATT&CK tactics
    """
    try:
        return run_analyst_agent(db, payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analyst Agent execution failed: {str(e)}",
        )


@router.post(
    "/orchestrate",
    response_model=SwarmOrchestrateResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger autonomous multi-agent swarm orchestration cycle",
)
def execute_swarm_orchestration(
    payload: SwarmOrchestratePayload,
    db: Session = Depends(get_db),
):
    """
    Triggers an end-to-end multi-agent orchestration cycle across all 5 agents:
    Planner -> Tool -> Analyst -> Critic -> Auditor.
    """
    try:
        return orchestrate_investigation_swarm(db, payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Swarm orchestration failed: {str(e)}",
        )
