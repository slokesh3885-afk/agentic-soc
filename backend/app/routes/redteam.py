"""
Module 3S: Critic & Red-Team Adversarial Evaluation Engine & Interactive Multi-Agent Pipeline Simulator Routes
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.redteam import (
    RedTeamChallengeRequest,
    RedTeamChallengeResponse,
    RedTeamScenarioPreset,
    InteractiveDemoSessionState,
)
from app.services.critic_redteam_service import (
    get_redteam_scenarios,
    execute_redteam_challenge,
    get_latest_redteam_challenge,
    execute_interactive_demo_step,
    get_demo_pipeline_state,
    reset_demo_pipeline,
)

router = APIRouter(prefix="", tags=["redteam"])


class StepExecutePayload(BaseModel):
    step_id: str = Field(..., description="Target step to execute (e.g. start_investigation, run_planner, collect_evidence, run_analysis, challenge_conclusion, audit_case, replay_investigation)")
    session_id: Optional[str] = Field("default-demo", description="Demo session identifier")


class ResetDemoPayload(BaseModel):
    session_id: Optional[str] = Field("default-demo", description="Demo session identifier")


@router.get(
    "/critic/redteam/scenarios",
    response_model=List[RedTeamScenarioPreset],
    status_code=status.HTTP_200_OK,
    summary="List available preset adversarial scenarios",
)
def list_redteam_scenarios():
    """Retrieve pre-packaged scenarios demonstrating Critic / Red-Team adversarial evaluation."""
    return get_redteam_scenarios()


@router.post(
    "/critic/redteam/challenge",
    response_model=RedTeamChallengeResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Critic / Red-Team adversarial attack on preliminary conclusion",
)
def run_redteam_challenge(
    request: RedTeamChallengeRequest,
    db: Session = Depends(get_db),
):
    """
    Execute deterministic Critic Agent attack on a preliminary investigator conclusion.
    Identifies evidence contradictions, validates persistence claims, evaluates reputation,
    enforces the Threat Actor Attribution Policy Guard, and renders a conclusive verdict.
    """
    return execute_redteam_challenge(db, request)


@router.get(
    "/critic/redteam/challenge/latest",
    response_model=RedTeamChallengeResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve latest Critic / Red-Team challenge result",
)
def get_latest_challenge(
    investigation_id: Optional[str] = Query(None, description="Optional investigation ID"),
    db: Session = Depends(get_db),
):
    """Retrieve the cached or default Critic adversarial challenge report."""
    return get_latest_redteam_challenge(db, investigation_id)


@router.get(
    "/demo/pipeline/state",
    response_model=InteractiveDemoSessionState,
    status_code=status.HTTP_200_OK,
    summary="Get current state of 7-stage interactive demo simulation",
)
def get_demo_state(
    session_id: Optional[str] = Query("default-demo", description="Demo session ID"),
    db: Session = Depends(get_db),
):
    """Retrieve state and telemetry history for the interactive prototype demo."""
    return get_demo_pipeline_state(db, session_id)


@router.post(
    "/demo/pipeline/step",
    response_model=InteractiveDemoSessionState,
    status_code=status.HTTP_200_OK,
    summary="Execute specific stage in interactive demo simulation",
)
def execute_demo_step(
    payload: StepExecutePayload,
    db: Session = Depends(get_db),
):
    """
    Deterministically execute one of the 7 interactive demo actions:
    start_investigation, run_planner, collect_evidence, run_analysis,
    challenge_conclusion, audit_case, or replay_investigation.
    """
    return execute_interactive_demo_step(db, payload.step_id, payload.session_id)


@router.post(
    "/demo/pipeline/reset",
    response_model=InteractiveDemoSessionState,
    status_code=status.HTTP_200_OK,
    summary="Reset interactive demo simulation state",
)
def reset_demo(
    payload: Optional[ResetDemoPayload] = None,
    db: Session = Depends(get_db),
):
    """Reset the 7-stage interactive demo simulation state back to Step 1."""
    sess_id = payload.session_id if payload else "default-demo"
    return reset_demo_pipeline(db, sess_id)
