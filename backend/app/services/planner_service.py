import json
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.plan import InvestigationPlanModel
from app.schemas.plan import PlanStep, InvestigationPlanResponse
from app.tools.registry import ToolRegistry


def generate_next_plan_id(db: Session) -> str:
    """Generate sequential plan ID (e.g. PLAN-001, PLAN-002)."""
    records = db.query(InvestigationPlanModel.id).all()
    max_num = 0
    pattern = re.compile(r"^PLAN-(\d+)$")

    for (rec_id,) in records:
        match = pattern.match(rec_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num

    return f"PLAN-{max_num + 1:03d}"


def build_deterministic_plan(alert_text: str, investigation_id: str, target_host: str = "") -> List[PlanStep]:
    """
    Deterministic rule-based planning engine.
    Analyzes the alert and host context to generate safe, sequential, allow-listed investigation steps.
    Strictly proposes steps using only registered tools; does NOT execute any tools or create Evidence.
    """
    clean_text = alert_text.lower()
    host_display = f" on {target_host}" if target_host else ""
    proposed_steps: List[PlanStep] = []
    step_num = 1

    # Rule 1: Always establish baseline event timeline via SIEM
    siem_action = (
        f"Search SIEM for related PowerShell event telemetry{host_display}"
        if "powershell" in clean_text
        else f"Search SIEM for correlated alert events{host_display}"
    )
    proposed_steps.append(
        PlanStep(
            step=step_num,
            action=siem_action,
            tool_name="siem_search",
            reason="Identify initial event timeline, command-line arguments, and correlated event logs",
            status="PROPOSED",
        )
    )
    step_num += 1

    # Rule 2: Host process lineage via EDR if process execution, powershell, or host context is present
    if any(k in clean_text for k in ["powershell", "process", "execution", "cmd", "exec", "parent", "host"]):
        proposed_steps.append(
            PlanStep(
                step=step_num,
                action=f"Search EDR for process lineage and parent-child tree{host_display}",
                tool_name="edr_process_search",
                reason="Determine parent/child process relationships, PID lineage, and execution context",
                status="PROPOSED",
            )
        )
        step_num += 1

    # Rule 3: Hash reputation lookup if hash indicator or hex digest pattern is detected
    hash_match = re.search(r"\b[a-f0-9]{32,64}\b", clean_text)
    if hash_match or any(k in clean_text for k in ["hash", "md5", "sha1", "sha256", "reputation"]):
        proposed_steps.append(
            PlanStep(
                step=step_num,
                action="Look up cryptographic hash reputation across threat intelligence feeds",
                tool_name="hash_lookup",
                reason="Determine whether suspect file hash has known malicious or benign reputation",
                status="PROPOSED",
            )
        )
        step_num += 1

    # Rule 4: Sandbox detonation if suspicious files, scripts, documents, or payload indicators exist
    if any(k in clean_text for k in ["file", "sample", "docm", "exe", "script", "payload", "attachment", "macro", "dropper"]):
        proposed_steps.append(
            PlanStep(
                step=step_num,
                action="Review automated sandbox behavioral detonation analysis",
                tool_name="sandbox_summary",
                reason="Inspect behavioral indicators, dropped files, and runtime persistence attempts",
                status="PROPOSED",
            )
        )
        step_num += 1

    # Rule 5: WHOIS / DNS lookup if domain, IP, or network communication indicators are present
    ip_or_domain = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_text) or any(
        k in clean_text for k in ["domain", "whois", "ip", "c2", "tunnel", "dns", "url", ".biz", ".test", ".com", "network"]
    )
    if ip_or_domain:
        proposed_steps.append(
            PlanStep(
                step=step_num,
                action="Query domain and IP registration metadata via WHOIS",
                tool_name="whois_lookup",
                reason="Evaluate domain age, registrar details, and infrastructure legitimacy",
                status="PROPOSED",
            )
        )
        step_num += 1

    # Rule 6: YARA rule scan if suspicious script, encoded command, or sample analysis is warranted
    if any(k in clean_text for k in ["yara", "encoded", "rule", "signature", "powershell", "sample"]):
        proposed_steps.append(
            PlanStep(
                step=step_num,
                action="Scan target scripts or samples against compiled YARA signature rules",
                tool_name="yara_scan",
                reason="Detect obfuscation techniques, encoded commands, and known adversary patterns",
                status="PROPOSED",
            )
        )
        step_num += 1

    # Strict Safety Verification: Ensure EVERY step references an allow-listed tool
    validated_steps: List[PlanStep] = []
    for s in proposed_steps:
        if ToolRegistry.is_allowlisted(s.tool_name):
            validated_steps.append(s)
        else:
            # Block and omit any tool that is not in the allow-list
            continue

    return validated_steps


def create_or_update_investigation_plan(
    db: Session,
    investigation_id: str,
    alert_override: Optional[str] = None,
) -> InvestigationPlanResponse:
    """
    Creates or updates a persistent investigation plan for the given investigation.
    Validates investigation existence. Does NOT execute any tools or create Evidence.
    """
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot generate plan: Investigation '{investigation_id}' does not exist.",
        )

    # Use alert override or fallback to investigation's alert title + description
    effective_alert = alert_override.strip() if alert_override and alert_override.strip() else inv.alert_name
    target_host = inv.target_host or ""

    # Generate deterministic plan steps
    steps = build_deterministic_plan(
        alert_text=effective_alert,
        investigation_id=investigation_id,
        target_host=target_host,
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Check if a plan already exists for this investigation
    existing_plan = (
        db.query(InvestigationPlanModel)
        .filter(InvestigationPlanModel.investigation_id == investigation_id)
        .first()
    )

    steps_json = json.dumps([s.model_dump() for s in steps])

    if existing_plan:
        existing_plan.alert = effective_alert
        existing_plan.plan_steps = steps_json
        existing_plan.status = "PROPOSED"
        existing_plan.created_at = now_utc
        db.commit()
        db.refresh(existing_plan)
        plan_record = existing_plan
    else:
        new_id = generate_next_plan_id(db)
        plan_record = InvestigationPlanModel(
            id=new_id,
            investigation_id=investigation_id,
            alert=effective_alert,
            plan_steps=steps_json,
            status="PROPOSED",
            created_at=now_utc,
        )
        db.add(plan_record)
        db.commit()
        db.refresh(plan_record)

    # Module 3K: Broadcast PLAN_PROPOSED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{investigation_id}",
            event_type="PLAN_PROPOSED",
            data={
                "plan_id": plan_record.id,
                "investigation_id": plan_record.investigation_id,
                "steps_count": len(steps),
                "planner_status": plan_record.status,
                "created_at": plan_record.created_at,
            },
            investigation_id=plan_record.investigation_id,
        )
    except Exception:
        pass

    return InvestigationPlanResponse(
        investigation_id=plan_record.investigation_id,
        alert=plan_record.alert,
        plan=steps,
        planner_status=plan_record.status,
        created_at=plan_record.created_at,
    )


def get_investigation_plan(
    db: Session,
    investigation_id: str,
) -> Optional[InvestigationPlanResponse]:
    """Retrieve existing investigation plan if one has been generated."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    plan_record = (
        db.query(InvestigationPlanModel)
        .filter(InvestigationPlanModel.investigation_id == investigation_id)
        .first()
    )

    if not plan_record:
        # If no plan generated yet, dynamically generate and persist initial plan
        return create_or_update_investigation_plan(db, investigation_id)

    try:
        raw_steps = json.loads(plan_record.plan_steps)
        steps = [PlanStep(**s) for s in raw_steps]
    except Exception:
        steps = []

    return InvestigationPlanResponse(
        investigation_id=plan_record.investigation_id,
        alert=plan_record.alert,
        plan=steps,
        planner_status=plan_record.status,
        created_at=plan_record.created_at,
    )
