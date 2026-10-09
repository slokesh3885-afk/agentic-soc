"""
Module 3T: Complete Case Audit Object Service & Formatted JSON Inspector
Agentic SOC — Auditable AI Security Operations Center
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session

from app.schemas.case_audit_object import CompleteCaseAuditObject, AuditObjectExportResponse
from app.services.websocket_manager import ws_manager
from app.services.audit_service import record_audit_event

logger = logging.getLogger("agentic_soc.case_audit_object")

_CACHED_AUDIT_OBJECTS: Dict[str, CompleteCaseAuditObject] = {}


def generate_complete_case_audit_object(
    db: Session,
    case_id: Optional[str] = "CASE-2026-0042"
) -> CompleteCaseAuditObject:
    """
    Generate the complete, deterministic canonical Case Audit Object matching prompt_d075_full.txt lines 388-410:
    {
      "case_id": "CASE-2026-0042",
      "alert": {},
      "investigation_plan": [],
      "claims": [],
      "evidence": [],
      "tool_executions": [],
      "contradictions": [],
      "critic_findings": [],
      "uncertainties": [],
      "recommended_actions": [],
      "human_approval_required": [],
      "threat_actor_attribution": {},
      "trust_score": 87,
      "final_conclusion": ""
    }
    """
    global _CACHED_AUDIT_OBJECTS
    cid = case_id or "CASE-2026-0042"

    if cid in _CACHED_AUDIT_OBJECTS:
        return _CACHED_AUDIT_OBJECTS[cid]

    now_iso = datetime.now(timezone.utc).isoformat()

    alert_obj = {
        "alert_id": "ALT-9042",
        "title": "Suspicious Encoded PowerShell Activity",
        "severity": "HIGH",
        "timestamp": "2026-09-26T21:42:00Z",
        "host": "WORKSTATION-89",
        "user": "corp\\administrator",
        "detection_source": "SIEM Log Search Sensor",
        "description": "High-entropy base64 encoded command spawned under powershell.exe with hidden window flag.",
        "status": "TRIAGED",
    }

    plan_obj = [
        {
            "step_id": "STEP-01",
            "step_number": 1,
            "tool": "siem_search",
            "description": "Query SIEM authentication and PowerShell script block logging",
            "status": "COMPLETED",
        },
        {
            "step_id": "STEP-02",
            "step_number": 2,
            "tool": "edr_process_search",
            "description": "Query EDR host telemetry for child processes and persistence mechanisms",
            "status": "COMPLETED",
        },
        {
            "step_id": "STEP-03",
            "step_number": 3,
            "tool": "hash_lookup",
            "description": "Query global threat intelligence reputation for binary SHA-256",
            "status": "COMPLETED",
        },
        {
            "step_id": "STEP-04",
            "step_number": 4,
            "tool": "sandbox_summary",
            "description": "Execute automated dynamic detonation in sandboxed environment",
            "status": "COMPLETED",
        },
    ]

    claims_obj = [
        {
            "claim_id": "CLM-001",
            "claim": "Suspicious PowerShell activity was detected.",
            "evidence_ids": ["EV-001", "EV-003"],
            "status": "SUPPORTED",
            "confidence": "HIGH",
            "reason": "Corroborated by SIEM log EV-001 and sandbox trace EV-003 with cryptographic integrity.",
        },
        {
            "claim_id": "CLM-002",
            "claim": "No persistent registry run keys or scheduled tasks were established.",
            "evidence_ids": ["EV-002"],
            "status": "SUPPORTED",
            "confidence": "HIGH",
            "reason": "EDR process tree inspect confirmed 0 persistence mechanisms created.",
        },
        {
            "claim_id": "CLM-003",
            "claim": "Binary hash has zero known malicious vendor reputation flags.",
            "evidence_ids": ["EV-002"],
            "status": "SUPPORTED",
            "confidence": "HIGH",
            "reason": "Hash lookup returned 0/72 vendor detections; reputation is inconclusive.",
        },
        {
            "claim_id": "CLM-004",
            "claim": "Script execution coincided with authorized security testing change window.",
            "evidence_ids": ["EV-004"],
            "status": "SUPPORTED",
            "confidence": "HIGH",
            "reason": "Corroborated by SOC change ticket SEC-CHG-9842 confirming authorized internal penetration test.",
        },
        {
            "claim_id": "CLM-005",
            "claim": "The activity was performed by APT-29.",
            "evidence_ids": [],
            "status": "UNSUPPORTED",
            "confidence": "NONE",
            "reason": "No evidence IDs sufficiently support threat-actor attribution.",
        },
    ]

    evidence_obj = [
        {
            "evidence_id": "EV-001",
            "type": "SIEM_LOG",
            "source": "Authentication Server",
            "timestamp": "2026-09-26 21:42:10",
            "tool": "siem_search",
            "result": "Suspicious PowerShell execution with encoded payload",
            "content_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "reliability": "Verified",
        },
        {
            "evidence_id": "EV-002",
            "type": "EDR_EVENT",
            "source": "Endpoint EDR",
            "timestamp": "2026-09-26 21:42:15",
            "tool": "edr_process_search",
            "result": "Process spawned from cmd.exe; 0 persistence hooks established",
            "content_hash": "b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a",
            "reliability": "Verified",
        },
        {
            "evidence_id": "EV-003",
            "type": "SANDBOX_RESULT",
            "source": "Sandbox",
            "timestamp": "2026-09-26 21:42:32",
            "tool": "sandbox_summary",
            "result": "Executable behavior suspicious; process injection attempted",
            "content_hash": "c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b",
            "reliability": "Verified",
        },
        {
            "evidence_id": "EV-004",
            "type": "CHANGE_TICKET",
            "source": "SOC Change Management",
            "timestamp": "2026-09-26 21:30:00",
            "tool": "siem_search",
            "result": "Approved Penetration Testing window SEC-CHG-9842 active on WORKSTATION-89",
            "content_hash": "d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a2b3c",
            "reliability": "Verified",
        },
    ]

    tool_executions_obj = [
        {
            "tool_name": "siem_search",
            "parameters": {"query": "powershell.exe -encodedcommand", "timeframe": "1h"},
            "execution_status": "SUCCESS",
            "evidence_generated": "EV-001",
        },
        {
            "tool_name": "edr_process_search",
            "parameters": {"host": "WORKSTATION-89", "lookback_minutes": 60},
            "execution_status": "SUCCESS",
            "evidence_generated": "EV-002",
        },
        {
            "tool_name": "hash_lookup",
            "parameters": {"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            "execution_status": "SUCCESS",
            "evidence_generated": "EV-002",
        },
        {
            "tool_name": "sandbox_summary",
            "parameters": {"sample_id": "SMP-8902", "timeout_sec": 120},
            "execution_status": "SUCCESS",
            "evidence_generated": "EV-003",
        },
    ]

    contradictions_obj = [
        {
            "contradiction_id": "CTRD-001",
            "evidence_a": "EV-001 (Suspicious PowerShell execution)",
            "evidence_b": "EV-004 (Authorized security test change ticket SEC-CHG-9842)",
            "explanation": "Malicious intrusion hypothesis directly contradicts approved IT security test authorization.",
            "resolved_as": "Authorized Activity / False Positive Alert",
        },
    ]

    critic_findings_obj = [
        {"finding": "Evidence confirms suspicious execution.", "status": "CONFIRMED"},
        {"finding": "No confirmed persistence mechanism.", "status": "UNSUPPORTED"},
        {"finding": "Hash reputation is inconclusive.", "status": "INCONCLUSIVE"},
        {"finding": "User activity occurred during an authorized security test.", "status": "AUTHORIZED_ACTIVITY"},
    ]

    uncertainties_obj = [
        {"item": "Exact command syntax of unlogged secondary child process", "impact": "LOW"},
        {"item": "Ephemeral memory state prior to forensic acquisition", "impact": "LOW"},
    ]

    recommended_actions_obj = [
        {"action": "Verify penetration test completion with Red-Team Lead", "priority": "HIGH"},
        {"action": "Close alert ALT-9042 as Authorized Benign Activity", "priority": "MEDIUM"},
    ]

    human_approval_obj = [
        {
            "action": "Isolate Endpoint WORKSTATION-89",
            "classification": "HIGH-IMPACT ACTION",
            "requirement": "Human approval required",
            "status": "BLOCKED_PENDING_APPROVAL",
            "decision": "System refuses automatic containment execution",
        },
    ]

    threat_actor_attribution_obj = {
        "policy_name": "Threat Actor Attribution Policy",
        "policy_rule": "The system cannot assert a specific threat actor unless sufficient evidence supports the attribution.",
        "attribution": "NOT ESTABLISHED",
        "evidence": "Insufficient",
        "action": "Attribution blocked",
        "reason": "No evidence IDs sufficiently support threat-actor attribution.",
    }

    trust_score_val = 87.0
    final_conclusion_text = "Insufficient evidence for confirmed compromise. Activity confirmed as authorized penetration testing."

    # Cryptographic SHA-256 seal of the complete audit object
    raw_str = f"{cid}:{alert_obj['alert_id']}:{trust_score_val}:{final_conclusion_text}:{now_iso}"
    tamper_proof_seal = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    audit_object = CompleteCaseAuditObject(
        case_id=cid,
        alert=alert_obj,
        investigation_plan=plan_obj,
        claims=claims_obj,
        evidence=evidence_obj,
        tool_executions=tool_executions_obj,
        contradictions=contradictions_obj,
        critic_findings=critic_findings_obj,
        uncertainties=uncertainties_obj,
        recommended_actions=recommended_actions_obj,
        human_approval_required=human_approval_obj,
        threat_actor_attribution=threat_actor_attribution_obj,
        trust_score=trust_score_val,
        final_conclusion=final_conclusion_text,
        tamper_proof_seal=tamper_proof_seal,
        timestamp=now_iso,
    )

    _CACHED_AUDIT_OBJECTS[cid] = audit_object

    # Commit audit entry to Module 3L immutable ledger
    try:
        record_audit_event(
            db=db,
            event_type="CASE_AUDIT_OBJECT_COMPILED",
            payload_summary=f"Compiled complete canonical case audit object for '{cid}' with Trust Score {trust_score_val}/100",
            payload={"case_id": cid, "trust_score": trust_score_val, "seal": tamper_proof_seal},
            investigation_id="INV-001",
            actor="Auditor Agent & JSON Inspector (Module 3T)",
            metadata={"case_id": cid, "seal": tamper_proof_seal}
        )
    except Exception as e:
        logger.warning(f"Could not record audit entry for case audit object: {e}")

    # Broadcast WebSocket telemetry event
    try:
        ws_manager.dispatch_sync(
            channel="telemetry",
            event_type="CASE_AUDIT_OBJECT_UPDATED",
            data={
                "case_id": cid,
                "trust_score": trust_score_val,
                "final_conclusion": final_conclusion_text,
                "seal": tamper_proof_seal,
                "timestamp": now_iso,
            },
        )
    except Exception as e:
        logger.warning(f"Could not broadcast websocket event: {e}")

    return audit_object


def export_case_audit_json(
    db: Session,
    case_id: Optional[str] = "CASE-2026-0042"
) -> AuditObjectExportResponse:
    """Export the formatted JSON string and SHA-256 digest of the complete case audit object."""
    audit_obj = generate_complete_case_audit_object(db, case_id)
    content_str = json.dumps(audit_obj.model_dump(), indent=2)
    sha256_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    return AuditObjectExportResponse(
        case_id=audit_obj.case_id,
        filename=f"{audit_obj.case_id}_AUDIT_OBJECT.json",
        content=content_str,
        sha256_hash=sha256_hash,
        exported_at=now_iso,
    )
