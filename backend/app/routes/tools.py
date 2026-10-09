import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.tool_execution import ToolExecutionModel
from app.schemas.tools import (
    ToolMetadataResponse,
    ToolExecuteRequest,
    ToolExecuteResponse,
    ToolExecutionAuditItem,
)
from app.tools.registry import ToolRegistry
from app.services.tool_service import (
    execute_security_tool,
    get_tool_executions_by_investigation,
)

router = APIRouter(tags=["tools"])


def _to_audit_item(model: ToolExecutionModel) -> ToolExecutionAuditItem:
    """Helper to deserialize input/output JSON strings for API response."""
    parsed_input = model.input
    parsed_output = model.output
    try:
        if isinstance(model.input, str):
            parsed_input = json.loads(model.input)
    except Exception:
        parsed_input = model.input

    try:
        if isinstance(model.output, str):
            parsed_output = json.loads(model.output)
    except Exception:
        parsed_output = model.output

    return ToolExecutionAuditItem(
        id=model.id,
        investigation_id=model.investigation_id,
        tool_name=model.tool_name,
        input=parsed_input,
        output=parsed_output,
        timestamp=model.timestamp,
        success=model.success,
        evidence_id=model.evidence_id,
        error=model.error,
    )


@router.get(
    "/tools",
    response_model=List[ToolMetadataResponse],
    summary="List all approved allow-listed security tools",
    tags=["tools"],
)
@router.get(
    "/tools/",
    response_model=List[ToolMetadataResponse],
    include_in_schema=False,
)
def list_allowlisted_tools():
    """
    Returns metadata and JSON schemas for all registered and allow-listed security tools:
    - siem_search
    - edr_process_search
    - hash_lookup
    - sandbox_summary
    - whois_lookup
    - yara_scan
    """
    return ToolRegistry.list_tools()


@router.post(
    "/tools/execute",
    response_model=ToolExecuteResponse,
    summary="Execute an allow-listed security tool and generate evidence",
    tags=["tools"],
)
@router.post(
    "/tools/execute/",
    response_model=ToolExecuteResponse,
    include_in_schema=False,
)
def execute_tool(
    request: ToolExecuteRequest,
    db: Session = Depends(get_db),
):
    """
    Execute one allow-listed tool.
    Strictly blocks unauthorized tools with {"success": false, "error": "TOOL_NOT_ALLOWLISTED"}.
    Upon success, automatically binds output to a persistent Evidence object with SHA-256 hash.
    Records a persistent audit log entry.
    """
    result = execute_security_tool(
        db=db,
        tool_name=request.tool_name,
        input_data=request.input,
        investigation_id=request.investigation_id or "INV-012",
    )
    return result


@router.get(
    "/investigations/{investigation_id}/tool-executions",
    response_model=List[ToolExecutionAuditItem],
    summary="List all tool executions for an investigation",
    tags=["tools"],
)
@router.get(
    "/investigations/{investigation_id}/tool-executions/",
    response_model=List[ToolExecutionAuditItem],
    include_in_schema=False,
)
def list_investigation_tool_executions(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """
    Returns the immutable audit log of all security tool calls made for an investigation,
    including inputs, outputs, timestamps, and corresponding Evidence IDs.
    """
    models = get_tool_executions_by_investigation(db, investigation_id)
    return [_to_audit_item(m) for m in models]
