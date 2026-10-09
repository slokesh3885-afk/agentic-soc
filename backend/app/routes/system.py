"""
Module 3U: Enterprise SOC Control Plane, Universal Omnibar Search & Notification Router
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.system import (
    SocSystemSettings,
    SocSystemSettingsUpdate,
    UniversalSearchResponse,
    NotificationsResponse,
)
from app.services.system_service import (
    get_soc_settings,
    update_soc_settings,
    perform_universal_search,
    get_soc_notifications,
    mark_notification_as_read,
    mark_all_notifications_as_read,
    reset_soc_settings,
    reset_soc_notifications,
)

router = APIRouter(prefix="/system", tags=["system"])


@router.get(
    "/settings",
    response_model=SocSystemSettings,
    status_code=status.HTTP_200_OK,
    summary="Get active SOC platform system configuration and control plane settings",
)
def get_system_settings():
    """Retrieve active platform settings, tool registry enforcement, and attribution policies."""
    return get_soc_settings()


@router.put(
    "/settings",
    response_model=SocSystemSettings,
    status_code=status.HTTP_200_OK,
    summary="Update SOC system configuration and control plane parameters",
)
def update_system_settings(update: SocSystemSettingsUpdate):
    """Update attribution strictness, tool timeout, trust score weights, and control policies."""
    return update_soc_settings(update)


@router.get(
    "/search",
    response_model=UniversalSearchResponse,
    status_code=status.HTTP_200_OK,
    summary="Universal omnibar search across all investigations, evidence, agents, alerts, and audit trail",
)
def search_system(
    q: str = Query(..., description="Omnibar search query string", min_length=1),
    db: Session = Depends(get_db),
):
    """Execute high-speed multi-entity search returning categorized matching entities."""
    return perform_universal_search(db=db, query=q)


@router.get(
    "/notifications",
    response_model=NotificationsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get real-time notification feed and unread counter",
)
def get_notifications():
    """Retrieve all operational security events and active notification alerts."""
    return get_soc_notifications()


@router.post(
    "/notifications/{notif_id}/read",
    status_code=status.HTTP_200_OK,
    summary="Mark a specific notification as read",
)
def mark_read(notif_id: str):
    """Mark an event notification as acknowledged/read."""
    success = mark_notification_as_read(notif_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification with ID '{notif_id}' not found.",
        )
    return {"status": "success", "id": notif_id, "read": True}


@router.post(
    "/notifications/mark-all-read",
    status_code=status.HTTP_200_OK,
    summary="Mark all active notifications as read",
)
def mark_all_read():
    """Mark all pending notifications as read and return count."""
    count = mark_all_notifications_as_read()
    return {"status": "success", "marked_read_count": count}


@router.post(
    "/settings/reset",
    response_model=SocSystemSettings,
    status_code=status.HTTP_200_OK,
    summary="Reset SOC platform settings to factory default configuration",
)
def reset_system_settings():
    """Reset all policy strictness, timeout, and trust score weights to initial system defaults."""
    return reset_soc_settings()


@router.post(
    "/notifications/seed",
    response_model=NotificationsResponse,
    status_code=status.HTTP_200_OK,
    summary="Seed or reset standard SOC notifications feed",
)
def seed_notifications():
    """Reset notifications feed to standard initial state."""
    return reset_soc_notifications()

