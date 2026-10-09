from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.critic import CriticRequest, CriticResponse
from app.services.critic_service import (
    evaluate_draft_conclusion,
    get_latest_critic_review,
)

router = APIRouter(tags=["critic"])


@router.post(
    "/investigations/{investigation_id}/critic",
    response_model=CriticResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate investigator draft conclusion via Critic / Red-Team Agent",
)
def run_critic_evaluation(
    investigation_id: str,
    payload: CriticRequest,
    db: Session = Depends(get_db),
):
    """
    Critic / Red-Team Agent endpoint.
    Challenging investigator draft conclusions and granular claims against verified evidence.
    Enforces strict threat actor attribution evidence, checks for missing or non-existent evidence IDs,
    detects contradictory evidence, and flags overconfident assertions.
    Does NOT execute tools or modify evidence.
    """
    return evaluate_draft_conclusion(db, investigation_id, payload)


@router.get(
    "/investigations/{investigation_id}/critic",
    response_model=CriticResponse,
    status_code=status.HTTP_200_OK,
    summary="Get latest Critic / Red-Team review for an investigation",
)
def get_critic_evaluation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve the most recent Critic / Red-Team evaluation review for the specified investigation.
    """
    review = get_latest_critic_review(db, investigation_id)
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No critic review found for investigation '{investigation_id}'.",
        )
    return review
