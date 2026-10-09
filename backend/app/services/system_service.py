"""
Module 3U: Enterprise SOC Control Plane, Universal Omnibar Search & Notification Service
Agentic SOC — Auditable AI Security Operations Center
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.models.agent import AgentModel
from app.models.audit_entry import AuditEntryModel
from app.schemas.system import (
    TrustScoreWeights,
    SocSystemSettings,
    SocSystemSettingsUpdate,
    SearchResultItem,
    UniversalSearchResponse,
    SocNotificationItem,
    NotificationsResponse,
)
from app.services.websocket_manager import ws_manager

logger = logging.getLogger("agentic_soc.system")

# In-memory settings state with robust enterprise defaults
_ACTIVE_SETTINGS: SocSystemSettings = SocSystemSettings(
    platform_name="Agentic SOC",
    tagline="Investigate → Challenge → Prove → Audit",
    environment="production-ready-prototype",
    backend_version="0.17.0",
    database_type="SQLite (Persistent)",
    database_path="backend/agentic_soc.db",
    tool_registry_enforcement=True,
    max_tool_execution_timeout_sec=120,
    allowlisted_tools_count=6,
    attribution_policy_strictness="STRICT",
    min_attribution_evidence_count=3,
    trust_score_weights=TrustScoreWeights(
        evidence_coverage=0.35,
        evidence_quality=0.25,
        contradiction_handling=0.20,
        attribution_support=0.10,
        replay_consistency=0.10,
    ),
    websocket_telemetry_active=True,
    merkle_sealing_enabled=True,
    updated_at=datetime.now(timezone.utc).isoformat(),
)

# In-memory notification center list
_NOTIFICATIONS_STORE: List[SocNotificationItem] = [
    SocNotificationItem(
        id="NOTIF-001",
        title="Attribution Guard Intercepted Assertion",
        message="Threat Actor Attribution Policy blocked uncorroborated assertion of 'APT-29' on INV-001.",
        severity="warning",
        timestamp=datetime.now(timezone.utc).isoformat(),
        read=False,
        category="ATTRIBUTION_BLOCKED",
        reference_id="INV-001",
    ),
    SocNotificationItem(
        id="NOTIF-002",
        title="Evidence Contradiction Flagged",
        message="Critic Agent detected contradiction between EV-001 (suspicious PowerShell) and EV-004 (authorized penetration test).",
        severity="info",
        timestamp=datetime.now(timezone.utc).isoformat(),
        read=False,
        category="CONTRADICTION",
        reference_id="EV-004",
    ),
    SocNotificationItem(
        id="NOTIF-003",
        title="Human Approval Required",
        message="High-impact containment action 'Isolate Endpoint WORKSTATION-89' requires manual human sign-off.",
        severity="critical",
        timestamp=datetime.now(timezone.utc).isoformat(),
        read=False,
        category="APPROVAL_REQUIRED",
        reference_id="INV-001",
    ),
    SocNotificationItem(
        id="NOTIF-004",
        title="Forensic Audit Trail Block Sealed",
        message="Cryptographic SHA-256 Merkle root sealed for case CASE-2026-0042 into immutable ledger.",
        severity="success",
        timestamp=datetime.now(timezone.utc).isoformat(),
        read=True,
        category="AUDIT_SEALED",
        reference_id="CASE-2026-0042",
    ),
]


def get_soc_settings() -> SocSystemSettings:
    """Retrieve active SOC platform system configuration."""
    return _ACTIVE_SETTINGS


def update_soc_settings(update: SocSystemSettingsUpdate) -> SocSystemSettings:
    """Update SOC system settings with validation."""
    global _ACTIVE_SETTINGS

    data = _ACTIVE_SETTINGS.model_dump()
    for field, val in update.model_dump(exclude_unset=True).items():
        if val is not None:
            data[field] = val

    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    _ACTIVE_SETTINGS = SocSystemSettings(**data)

    # Broadcast updated settings via WebSocket
    try:
        ws_manager.dispatch_sync(
            channel="telemetry",
            event_type="SYSTEM_SETTINGS_UPDATED",
            data={
                "attribution_strictness": _ACTIVE_SETTINGS.attribution_policy_strictness,
                "min_sources": _ACTIVE_SETTINGS.min_attribution_evidence_count,
                "timeout_sec": _ACTIVE_SETTINGS.max_tool_execution_timeout_sec,
                "timestamp": _ACTIVE_SETTINGS.updated_at,
            },
        )
    except Exception as e:
        logger.warning(f"Could not broadcast settings update: {e}")

    return _ACTIVE_SETTINGS


def perform_universal_search(db: Session, query: str) -> UniversalSearchResponse:
    """
    Execute high-speed universal omnibar search across all SOC entities:
    - Investigations
    - Evidence
    - Agents
    - Audit Trail
    - Alerts
    """
    q = (query or "").strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()

    if not q:
        return UniversalSearchResponse(
            query=query,
            total_matches=0,
            categories={},
            results=[],
            searched_at=now_iso,
        )

    results: List[SearchResultItem] = []
    category_counts: Dict[str, int] = {
        "investigations": 0,
        "evidence": 0,
        "agents": 0,
        "audit_trail": 0,
        "alerts": 0,
    }

    # 1. Search Investigations & Alerts
    try:
        invs = db.query(InvestigationModel).all()
        for inv in invs:
            inv_title = getattr(inv, "alert_name", "") or getattr(inv, "title", "")
            inv_host = getattr(inv, "target_host", "") or getattr(inv, "host", "")
            title_match = q in inv_title.lower()
            desc_match = q in (inv.description or "").lower()
            inv_id_lower = (inv.id or "").lower()
            id_match = (
                q in inv_id_lower
                or q.replace("case-", "inv-") in inv_id_lower
                or q.replace("inv-", "case-") in inv_id_lower
            )
            host_match = q in inv_host.lower()

            if title_match or desc_match or id_match or host_match:
                results.append(
                    SearchResultItem(
                        id=inv.id,
                        category="investigations",
                        title=f"{inv.id}: {inv_title}",
                        description=inv.description or f"Investigation on {inv_host}",
                        severity_or_status=inv.status,
                        timestamp=str(inv.created_at) if hasattr(inv, "created_at") else None,
                        route=f"investigations/{inv.id}",
                    )
                )
                category_counts["investigations"] += 1

            # Match Alert
            alert_id = getattr(inv, "alert_id", None) or f"ALT-{inv.id.replace('INV-', '')}"
            if q in alert_id.lower() or "alert" in q or (q.startswith("alt-") and q.replace("alt-", "") in alert_id.lower()):
                results.append(
                    SearchResultItem(
                        id=alert_id,
                        category="alerts",
                        title=f"{alert_id}: Alert for {inv_title}",
                        description=f"Ingested alert telemetry bound to {inv.id}",
                        severity_or_status=getattr(inv, "severity", "HIGH"),
                        timestamp=str(inv.created_at) if hasattr(inv, "created_at") else None,
                        route="alerts",
                    )
                )
                category_counts["alerts"] += 1
    except Exception as e:
        logger.warning(f"Error searching investigations: {e}")

    # 2. Search Evidence items
    try:
        evs = db.query(EvidenceModel).all()
        for ev in evs:
            ev_id_lower = (ev.id or "").lower()
            id_match = (
                q in ev_id_lower
                or q.replace("ev-", "e-") in ev_id_lower
                or q.replace("e-", "ev-") in ev_id_lower
            )
            type_match = q in (ev.evidence_type or "").lower()
            source_match = q in (ev.source or "").lower()
            output_match = q in (ev.raw_output or "").lower()

            if id_match or type_match or source_match or output_match:
                results.append(
                    SearchResultItem(
                        id=ev.id,
                        category="evidence",
                        title=f"{ev.id} ({ev.evidence_type})",
                        description=f"Source: {ev.source} — {ev.raw_output[:80]}...",
                        severity_or_status="Verified",
                        timestamp=str(ev.timestamp) if hasattr(ev, "timestamp") else None,
                        route="evidence",
                    )
                )
                category_counts["evidence"] += 1
    except Exception as e:
        logger.warning(f"Error searching evidence: {e}")

    # 3. Search Agents
    try:
        agents = db.query(AgentModel).all()
        for ag in agents:
            id_match = q in (ag.id or "").lower()
            name_match = q in (ag.name or "").lower()
            role_match = q in (ag.role or "").lower()
            task_match = q in (ag.current_task or "").lower()

            if id_match or name_match or role_match or task_match:
                results.append(
                    SearchResultItem(
                        id=ag.id,
                        category="agents",
                        title=f"{ag.name} ({ag.role})",
                        description=f"Status: {ag.status} — Task: {ag.current_task}",
                        severity_or_status=ag.status,
                        timestamp=None,
                        route="agents",
                    )
                )
                category_counts["agents"] += 1
    except Exception as e:
        logger.warning(f"Error searching agents: {e}")

    # 4. Search Audit Trail
    try:
        entries = db.query(AuditEntryModel).limit(30).all()
        for ent in entries:
            id_match = q in (ent.id or "").lower()
            action_type = getattr(ent, "event_type", "") or getattr(ent, "action_type", "")
            action_match = q in action_type.lower()
            actor_match = q in (ent.actor or "").lower()
            detail_match = q in (ent.payload_summary or "").lower()

            if id_match or action_match or actor_match or detail_match:
                sig = getattr(ent, "signature", None) or getattr(ent, "seal_signature", None)
                results.append(
                    SearchResultItem(
                        id=ent.id,
                        category="audit_trail",
                        title=f"{ent.id}: {action_type}",
                        description=f"Actor: {ent.actor} — {ent.payload_summary}",
                        severity_or_status=sig[:10] if sig else "VALID",
                        timestamp=ent.timestamp,
                        route="audit-trail",
                    )
                )
                category_counts["audit_trail"] += 1
    except Exception as e:
        logger.warning(f"Error searching audit entries: {e}")

    # Deduplicate and sort by relevance
    seen_ids = set()
    deduped = []
    for r in results:
        key = f"{r.category}:{r.id}"
        if key not in seen_ids:
            seen_ids.add(key)
            deduped.append(r)

    # Rank exact ID and title matches higher than raw body text matches
    def rank_match(item: SearchResultItem):
        title_lower = item.title.lower()
        id_lower = item.id.lower()
        if q == id_lower or q == title_lower:
            return 0
        if q in id_lower:
            return 1
        if q in title_lower:
            return 2
        if item.category in ("agents", "investigations", "alerts"):
            return 3
        return 4

    deduped.sort(key=rank_match)

    return UniversalSearchResponse(
        query=query,
        total_matches=len(deduped),
        categories=category_counts,
        results=deduped[:50],
        searched_at=now_iso,
    )


def get_soc_notifications() -> NotificationsResponse:
    """Retrieve all current notifications in the notification center."""
    unread = sum(1 for n in _NOTIFICATIONS_STORE if not n.read)
    return NotificationsResponse(
        total_notifications=len(_NOTIFICATIONS_STORE),
        unread_count=unread,
        notifications=_NOTIFICATIONS_STORE,
    )


def mark_notification_as_read(notif_id: str) -> bool:
    """Mark a specific notification as read."""
    global _NOTIFICATIONS_STORE
    for n in _NOTIFICATIONS_STORE:
        if n.id == notif_id:
            n.read = True
            return True
    return False


def mark_all_notifications_as_read() -> int:
    """Mark all notifications as read."""
    global _NOTIFICATIONS_STORE
    count = 0
    for n in _NOTIFICATIONS_STORE:
        if not n.read:
            n.read = True
            count += 1
    return count


def reset_soc_settings() -> SocSystemSettings:
    """Reset SOC system settings to factory defaults."""
    global _ACTIVE_SETTINGS
    _ACTIVE_SETTINGS = SocSystemSettings(
        platform_name="Agentic SOC",
        tagline="Investigate -> Challenge -> Prove -> Audit",
        environment="production-ready-prototype",
        backend_version="0.17.0",
        database_type="SQLite (Persistent)",
        database_path="backend/agentic_soc.db",
        tool_registry_enforcement=True,
        max_tool_execution_timeout_sec=120,
        allowlisted_tools_count=6,
        attribution_policy_strictness="STRICT",
        min_attribution_evidence_count=3,
        trust_score_weights=TrustScoreWeights(
            evidence_coverage=0.35,
            evidence_quality=0.25,
            contradiction_handling=0.20,
            attribution_support=0.10,
            replay_consistency=0.10,
        ),
        websocket_telemetry_active=True,
        merkle_sealing_enabled=True,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    return _ACTIVE_SETTINGS


def reset_soc_notifications() -> NotificationsResponse:
    """Reset notification store to initial seed state."""
    global _NOTIFICATIONS_STORE
    _NOTIFICATIONS_STORE = [
        SocNotificationItem(
            id="NOTIF-001",
            title="Attribution Guard Intercepted Assertion",
            message="Threat Actor Attribution Policy blocked uncorroborated assertion of 'APT-29' on INV-001.",
            severity="warning",
            timestamp=datetime.now(timezone.utc).isoformat(),
            read=False,
            category="ATTRIBUTION_BLOCKED",
            reference_id="INV-001",
        ),
        SocNotificationItem(
            id="NOTIF-002",
            title="Evidence Contradiction Flagged",
            message="Critic Agent detected contradiction between EV-001 (suspicious PowerShell) and EV-004 (authorized penetration test).",
            severity="info",
            timestamp=datetime.now(timezone.utc).isoformat(),
            read=False,
            category="CONTRADICTION",
            reference_id="EV-004",
        ),
        SocNotificationItem(
            id="NOTIF-003",
            title="Human Approval Required",
            message="High-impact containment action 'Isolate Endpoint WORKSTATION-89' requires manual human sign-off.",
            severity="critical",
            timestamp=datetime.now(timezone.utc).isoformat(),
            read=False,
            category="APPROVAL_REQUIRED",
            reference_id="INV-001",
        ),
        SocNotificationItem(
            id="NOTIF-004",
            title="Forensic Audit Trail Block Sealed",
            message="Cryptographic SHA-256 Merkle root sealed for case CASE-2026-0042 into immutable ledger.",
            severity="success",
            timestamp=datetime.now(timezone.utc).isoformat(),
            read=True,
            category="AUDIT_SEALED",
            reference_id="CASE-2026-0042",
        ),
    ]
    return get_soc_notifications()

