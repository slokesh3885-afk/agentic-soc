from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.plan import PlanCreateRequest, InvestigationPlanResponse
from app.services.planner_service import (
    create_or_update_investigation_plan,
    get_investigation_plan,
)

router = APIRouter(tags=["planner"])


@router.post(
    "/investigations/{investigation_id}/plan",
    response_model=InvestigationPlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate or update a deterministic investigation plan",
)
@router.post(
    "/investigations/{investigation_id}/plan/",
    response_model=InvestigationPlanResponse,
    include_in_schema=False,
)
def generate_plan(
    investigation_id: str,
    request: PlanCreateRequest = PlanCreateRequest(),
    db: Session = Depends(get_db),
):
    """
    Analyzes alert telemetry and generates an ordered, safe investigation plan.
    All proposed actions reference ONLY allow-listed security tools from the Tool Registry.
    Does NOT execute tools or create Evidence objects.
    """
    return create_or_update_investigation_plan(
        db=db,
        investigation_id=investigation_id,
        alert_override=request.alert,
    )


@router.get(
    "/investigations/{investigation_id}/plan",
    response_model=InvestigationPlanResponse,
    summary="Retrieve the current investigation plan",
)
@router.get(
    "/investigations/{investigation_id}/plan/",
    response_model=InvestigationPlanResponse,
    include_in_schema=False,
)
def get_plan(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """
    Returns the current investigation plan. If no plan has been created yet,
    the Planner Agent automatically derives and persists the initial plan.
    """
    return get_investigation_plan(db, investigation_id)
