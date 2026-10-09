import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.investigation import InvestigationModel
from app.models.tool_execution import ToolExecutionModel
from app.schemas.evidence import EvidenceCreate, EvidenceType
from app.services.evidence_service import create_evidence
from app.tools.registry import ToolRegistry


def generate_next_execution_id(db: Session) -> str:
    """Generate sequential tool execution ID (e.g. EXEC-001, EXEC-002)."""
    records = db.query(ToolExecutionModel.id).all()
    max_num = 0
    pattern = re.compile(r"^EXEC-(\d+)$")

    for (rec_id,) in records:
        match = pattern.match(rec_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num

    return f"EXEC-{max_num + 1:03d}"


def execute_security_tool(
    db: Session,
    tool_name: str,
    input_data: Dict[str, Any],
    investigation_id: str = "INV-012",
) -> Dict[str, Any]:
    """
    Executes an allow-listed security tool, binds output to an Evidence object,
    and creates a persistent audit log entry.
    Strictly blocks and records any unapproved tool execution attempt.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. SECURITY BOUNDARY CHECK: Enforce explicit allow-list
    if not ToolRegistry.is_allowlisted(tool_name):
        exec_id = generate_next_execution_id(db)
        audit_record = ToolExecutionModel(
            id=exec_id,
            investigation_id=investigation_id if investigation_id else "UNKNOWN",
            tool_name=tool_name,
            input=json.dumps(input_data) if input_data else "{}",
            output=json.dumps({"error": "TOOL_NOT_ALLOWLISTED"}),
            timestamp=now_utc,
            success=False,
            evidence_id=None,
            error="TOOL_NOT_ALLOWLISTED",
        )
        db.add(audit_record)
        db.commit()

        return {
            "tool_name": tool_name,
            "success": False,
            "timestamp": now_utc,
            "data": None,
            "evidence_id": None,
            "error": "TOOL_NOT_ALLOWLISTED",
        }

    # 2. Retrieve tool instance
    tool = ToolRegistry.get_tool(tool_name)
    if not tool or not tool.enabled:
        return {
            "tool_name": tool_name,
            "success": False,
            "timestamp": now_utc,
            "data": None,
            "evidence_id": None,
            "error": "TOOL_DISABLED",
        }

    # 3. Validate parent investigation exists
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot execute tool: Investigation '{investigation_id}' does not exist.",
        )

    # 4. Execute tool logic with safety validation
    try:
        execution_result = tool.run(input_data)
        tool_data = execution_result["data"]
    except ValueError as val_err:
        exec_id = generate_next_execution_id(db)
        err_msg = str(val_err)
        audit_record = ToolExecutionModel(
            id=exec_id,
            investigation_id=investigation_id,
            tool_name=tool_name,
            input=json.dumps(input_data),
            output=json.dumps({"error": err_msg}),
            timestamp=now_utc,
            success=False,
            evidence_id=None,
            error=err_msg,
        )
        db.add(audit_record)
        db.commit()
        return {
            "tool_name": tool_name,
            "success": False,
            "timestamp": now_utc,
            "data": None,
            "evidence_id": None,
            "error": err_msg,
        }

    # 5. AUTOMATIC EVIDENCE GENERATION: Map tool output to Evidence Engine
    evidence_query = (
        input_data.get("query")
        or input_data.get("host")
        or input_data.get("hash")
        or input_data.get("sample_id")
        or input_data.get("domain")
        or json.dumps(input_data)
    )

    # Format raw output deterministically for forensic hashing
    formatted_raw_output = json.dumps(tool_data, indent=2, sort_keys=True)

    # Validate or map evidence type
    try:
        ev_type = EvidenceType(tool.evidence_type)
    except Exception:
        ev_type = EvidenceType.OTHER

    evidence_payload = EvidenceCreate(
        evidence_type=ev_type,
        source=f"Tool: {tool.name}",
        query=f"{tool.name}({evidence_query})",
        raw_output=formatted_raw_output,
        timestamp=now_utc,
        status="VERIFIED",
    )

    # Persist evidence object through Evidence Engine
    evidence_model = create_evidence(db, investigation_id, evidence_payload)

    # 6. Record Audit Log in tool_executions table
    exec_id = generate_next_execution_id(db)
    audit_record = ToolExecutionModel(
        id=exec_id,
        investigation_id=investigation_id,
        tool_name=tool_name,
        input=json.dumps(input_data),
        output=json.dumps(tool_data),
        timestamp=now_utc,
        success=True,
        evidence_id=evidence_model.id,
        error=None,
    )
    db.add(audit_record)
    db.commit()

    # Module 3K: Broadcast TOOL_EXECUTED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{investigation_id}",
            event_type="TOOL_EXECUTED",
            data={
                "execution_id": exec_id,
                "investigation_id": investigation_id,
                "tool_name": tool_name,
                "evidence_id": evidence_model.id,
                "content_hash": evidence_model.content_hash,
                "success": True,
                "timestamp": now_utc,
            },
            investigation_id=investigation_id,
        )
    except Exception:
        pass

    return {
        "tool_name": tool_name,
        "success": True,
        "timestamp": now_utc,
        "data": tool_data,
        "evidence_id": evidence_model.id,
        "error": None,
    }


def get_tool_executions_by_investigation(
    db: Session,
    investigation_id: str,
) -> List[ToolExecutionModel]:
    """Retrieve all auditable tool executions for an investigation."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' does not exist.",
        )

    return (
        db.query(ToolExecutionModel)
        .filter(ToolExecutionModel.investigation_id == investigation_id)
        .order_by(ToolExecutionModel.id.asc())
        .all()
    )


def seed_initial_tool_executions(db: Session) -> None:
    """
    Seed initial tool execution logs for INV-012 if empty,
    demonstrating audit correlation with seeded evidence E-001 and E-002.
    """
    if db.query(ToolExecutionModel).count() > 0:
        return

    now_utc = "2026-09-27 16:05:00 UTC"
    executions = [
        ToolExecutionModel(
            id="EXEC-001",
            investigation_id="INV-012",
            tool_name="siem_search",
            input=json.dumps({"query": "host=PC-DB-TEST powershell"}),
            output=json.dumps({
                "query": "host=PC-DB-TEST powershell",
                "total_matches": 2,
                "events": [
                    {
                        "timestamp": "2026-09-27T16:05:00Z",
                        "host": "PC-DB-TEST",
                        "process": "powershell.exe",
                        "parent_process": "unknown_process.exe",
                        "event_id": "4688",
                    }
                ],
            }),
            timestamp=now_utc,
            success=True,
            evidence_id="E-001",
            error=None,
        ),
        ToolExecutionModel(
            id="EXEC-002",
            investigation_id="INV-012",
            tool_name="edr_process_search",
            input=json.dumps({"host": "PC-DB-TEST"}),
            output=json.dumps({
                "host": "PC-DB-TEST",
                "lineage_summary": "winword.exe (PID 4812) -> powershell.exe (PID 5920) -> cmd.exe (PID 6312)",
                "total_processes": 3,
            }),
            timestamp="2026-09-27 16:07:30 UTC",
            success=True,
            evidence_id="E-002",
            error=None,
        ),
    ]

    for item in executions:
        db.add(item)
    db.commit()
