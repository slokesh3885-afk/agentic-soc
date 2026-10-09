"""
Module 3M — Incident Cases Dossier & MITRE ATT&CK Matrix Routes
Agentic SOC — Auditable AI Security Operations Center

API endpoints for accessing multi-agent incident dossiers, MITRE ATT&CK technique mappings,
forensic chain-of-custody transfer logs, and MITRE Navigator layer exports.
"""

import json
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.dossier import IncidentDossierModel
from app.schemas.dossier import (
    IncidentDossierSchema,
    MitreMatrixSummaryResponse,
)
from app.services.dossier_service import (
    get_or_create_dossier,
    refresh_dossier,
    get_mitre_matrix_summary,
    generate_navigator_layer,
    seed_initial_dossiers,
)

router = APIRouter(prefix="/dossiers", tags=["dossiers"])


def _format_dossier_schema(model: IncidentDossierModel) -> IncidentDossierSchema:
    """Helper to convert SQLAlchemy model with JSON strings into Pydantic schema."""
    return IncidentDossierSchema(
        id=model.id,
        investigation_id=model.investigation_id,
        title=model.title,
        severity=model.severity,
        status=model.status,
        threat_actor_attribution=model.threat_actor_attribution,
        primary_tactic=model.primary_tactic,
        mitre_techniques=json.loads(model.mitre_techniques_json) if model.mitre_techniques_json else [],
        custody_chain=json.loads(model.custody_chain_json) if model.custody_chain_json else [],
        summary=model.summary,
        recommendations=json.loads(model.recommendations_json) if model.recommendations_json else [],
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


@router.get(
    "",
    response_model=List[IncidentDossierSchema],
    summary="List Incident Cases Dossiers",
    description="Retrieve all incident dossiers mapped to the MITRE ATT&CK framework with complete forensic chains of custody.",
)
def list_dossiers(
    severity: Optional[str] = Query(None, description="Filter by severity: Critical, High, Medium, Low"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: Open, Under Review, Contained, Closed"),
    tactic: Optional[str] = Query(None, description="Filter by primary MITRE tactic (e.g. Execution, Command and Control)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    seed_initial_dossiers(db)
    query = db.query(IncidentDossierModel)

    if severity:
        query = query.filter(IncidentDossierModel.severity == severity)
    if status_filter:
        query = query.filter(IncidentDossierModel.status == status_filter)
    if tactic:
        query = query.filter(IncidentDossierModel.primary_tactic == tactic)

    models = query.order_by(desc(IncidentDossierModel.created_at)).offset(offset).limit(limit).all()
    return [_format_dossier_schema(m) for m in models]


@router.get(
    "/matrix/summary",
    response_model=MitreMatrixSummaryResponse,
    summary="Get Enterprise MITRE ATT&CK Matrix Summary",
    description="Retrieve coverage analytics, technique counts, and tactics breakdown across all incident cases.",
)
def matrix_summary(db: Session = Depends(get_db)):
    summary = get_mitre_matrix_summary(db)
    return summary


@router.get(
    "/investigation/{investigation_id}",
    response_model=IncidentDossierSchema,
    summary="Get Dossier by Investigation ID",
    description="Retrieve or dynamically synthesize an incident dossier for a specific investigation.",
)
def get_dossier_by_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    try:
        model = get_or_create_dossier(db, investigation_id)
        return _format_dossier_schema(model)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/refresh/{investigation_id}",
    response_model=IncidentDossierSchema,
    summary="Refresh Investigation Dossier",
    description="Re-synthesize an investigation's dossier with latest multi-agent outputs, evidence items, and custody chain.",
)
def refresh_investigation_dossier(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    try:
        model = refresh_dossier(db, investigation_id)
        return _format_dossier_schema(model)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{dossier_id}/navigator",
    summary="Export MITRE ATT&CK Navigator Layer",
    description="Export a standardized MITRE ATT&CK Navigator JSON layer for visual matrix exploration.",
)
def export_navigator_layer(
    dossier_id: str,
    db: Session = Depends(get_db),
):
    try:
        layer = generate_navigator_layer(db, dossier_id)
        return layer
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{dossier_id}",
    response_model=IncidentDossierSchema,
    summary="Get Dossier by Unique ID",
    description="Retrieve a specific incident dossier by its identifier (e.g. DOS-001).",
)
def get_dossier(
    dossier_id: str,
    db: Session = Depends(get_db),
):
    model = db.query(IncidentDossierModel).filter(IncidentDossierModel.id == dossier_id).first()
    if not model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Dossier {dossier_id} not found.")
    return _format_dossier_schema(model)
