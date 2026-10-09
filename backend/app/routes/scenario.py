"""
Scenario Routes (Module 3H)
Agentic SOC — Auditable AI Security Operations Center

Exposes REST APIs for executing and retrieving deterministic synthetic test scenarios.
Demonstrates the full end-to-end multi-agent SOC pipeline (Evidence Engine -> Planner ->
Critic -> Auditor -> Case JSON -> Trust Score) in a controlled, isolated demonstration environment.
All data is strictly synthetic.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.scenario import TruePositiveScenarioResponse
from app.schemas.scenario_trap import TrapScenarioResponse
from app.services.scenario_service import (
    run_true_positive_scenario,
    get_true_positive_scenario,
)
from app.services.scenario_trap_service import (
    run_trap_scenario,
    get_trap_scenario,
)

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


@router.post(
    "/true-positive",
    response_model=TruePositiveScenarioResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic Synthetic True Positive Scenario (Module 3H)",
)
def execute_true_positive_scenario(
    db: Session = Depends(get_db),
):
    """
    Executes the deterministic Synthetic True Positive Scenario through the complete
    auditable SOC pipeline.
    """
    return run_true_positive_scenario(db, force_reset=True)


@router.get(
    "/true-positive",
    response_model=TruePositiveScenarioResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current state of Synthetic True Positive Scenario (Module 3H)",
)
def fetch_true_positive_scenario(
    db: Session = Depends(get_db),
):
    """
    Retrieves the current state of the Synthetic True Positive demonstration scenario.
    """
    return get_true_positive_scenario(db)


@router.post(
    "/trap",
    response_model=TrapScenarioResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic Synthetic Trap / Deception Scenario (Module 3I)",
)
def execute_trap_scenario(
    db: Session = Depends(get_db),
):
    """
    Executes the deterministic Synthetic Trap / Deception Scenario (Module 3I)
    through the complete auditable SOC pipeline:
    1. Forensic Evidence Engine (seeded with conflicting telemetry)
    2. Planner Agent (investigation plan)
    3. Critic Agent (actively challenges conclusion, detects contradiction between
       suspicious script and approved maintenance ticket CHG-99214, flags overclaims)
    4. Auditor Agent (enforces conflict resolution, marks claim CONTRADICTED,
       verifies NO EVIDENCE -> NO CLAIM)
    5. Canonical Case JSON (Module 3F validated export)
    6. Evidence Trust Score (computes contradiction deductions, lower trust score)

    Demonstrates that the multi-agent pipeline detects deceptive signals rather
    than blindly accepting false positive or unverified conclusions.
    All data is strictly synthetic test values.
    """
    return run_trap_scenario(db, force_reset=True)


@router.get(
    "/trap",
    response_model=TrapScenarioResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current state of Synthetic Trap / Deception Scenario (Module 3I)",
)
def fetch_trap_scenario(
    db: Session = Depends(get_db),
):
    """
    Retrieves the current state of the Synthetic Trap / Deception demonstration scenario.
    """
    return get_trap_scenario(db)
