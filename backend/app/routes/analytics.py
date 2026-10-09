"""
Module 3V: Overview Dashboard Analytics & Multi-Chart Engine Router
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.analytics import (
    PostureSummary,
    OverviewAnalyticsResponse,
    AlertsOverTimePoint,
    InvestigationOutcomeDistribution,
    EvidenceSourceDistribution,
    TrustScoreHistoryPoint,
)
from app.services.analytics_service import (
    get_security_posture_summary,
    get_overview_analytics,
    get_alerts_over_time,
    get_investigation_outcomes,
    get_evidence_sources_distribution,
    get_trust_score_history,
)

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get(
    "/overview",
    response_model=OverviewAnalyticsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get complete aggregated overview analytics and all 4 dashboard charts",
)
def fetch_overview_analytics(db: Session = Depends(get_db)):
    """Returns composite posture index, alerts over time, outcomes, evidence sources, and trust history."""
    return get_overview_analytics(db)


@router.get(
    "/posture",
    response_model=PostureSummary,
    status_code=status.HTTP_200_OK,
    summary="Get real-time enterprise security posture summary and SOC KPIs",
)
def fetch_security_posture(db: Session = Depends(get_db)):
    """Computes active security posture status, composite trust score, and evidence coverage percentage."""
    return get_security_posture_summary(db)


@router.get(
    "/charts",
    status_code=status.HTTP_200_OK,
    summary="Get raw data arrays for all 4 required overview charts",
)
def fetch_charts_data(db: Session = Depends(get_db)):
    """Retrieves alerts_over_time, investigation_outcomes, evidence_sources, and trust_score_history."""
    return {
        "alerts_over_time": get_alerts_over_time(db),
        "investigation_outcomes": get_investigation_outcomes(db),
        "evidence_sources": get_evidence_sources_distribution(db),
        "trust_score_history": get_trust_score_history(db),
    }


@router.get(
    "/outcomes",
    response_model=List[InvestigationOutcomeDistribution],
    status_code=status.HTTP_200_OK,
    summary="Get investigation outcomes distribution",
)
def fetch_outcomes(db: Session = Depends(get_db)):
    return get_investigation_outcomes(db)


@router.get(
    "/evidence-sources",
    response_model=List[EvidenceSourceDistribution],
    status_code=status.HTTP_200_OK,
    summary="Get evidence artifacts distribution across source tool types",
)
def fetch_evidence_sources(db: Session = Depends(get_db)):
    return get_evidence_sources_distribution(db)


@router.get(
    "/trust-history",
    response_model=List[TrustScoreHistoryPoint],
    status_code=status.HTTP_200_OK,
    summary="Get trust score history across investigations",
)
def fetch_trust_history(db: Session = Depends(get_db)):
    return get_trust_score_history(db)


@router.get(
    "/alerts-timeline",
    response_model=List[AlertsOverTimePoint],
    status_code=status.HTTP_200_OK,
    summary="Get alerts over time chronological progression",
)
def fetch_alerts_timeline(db: Session = Depends(get_db)):
    return get_alerts_over_time(db)
