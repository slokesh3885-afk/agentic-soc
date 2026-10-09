import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ToolMetadataResponse(BaseModel):
    """Metadata schema describing an allow-listed security tool."""
    tool_name: str
    description: str
    evidence_type: str
    enabled: bool = True
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]


class ToolExecuteRequest(BaseModel):
    """Payload sent by an agent or analyst to execute a registered security tool."""
    tool_name: str = Field(..., min_length=1, description="Registered allow-listed tool name")
    input: Dict[str, Any] = Field(default_factory=dict, description="Tool input arguments")
    investigation_id: Optional[str] = Field(
        default="INV-012",
        description="Target investigation ID to bind the resulting Evidence object to",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "tool_name" not in data and "toolName" in data:
                data["tool_name"] = data["toolName"]
            if "investigation_id" not in data and "investigationId" in data:
                data["investigation_id"] = data["investigationId"]
        return data


class ToolExecuteResponse(BaseModel):
    """Standardized response from tool execution."""
    tool_name: str
    success: bool
    timestamp: str
    data: Optional[Dict[str, Any]] = None
    evidence_id: Optional[str] = None
    error: Optional[str] = None


class ToolExecutionAuditItem(BaseModel):
    """Auditable log record of a past tool execution."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    tool_name: str
    input: Any
    output: Any
    timestamp: str
    success: bool
    evidence_id: Optional[str] = None
    error: Optional[str] = None

    # Frontend camelCase aliases
    executionId: Optional[str] = None
    investigationId: Optional[str] = None
    toolName: Optional[str] = None
    evidenceId: Optional[str] = None

    @model_validator(mode="after")
    def populate_aliases(self) -> "ToolExecutionAuditItem":
        if self.executionId is None:
            self.executionId = self.id
        if self.investigationId is None:
            self.investigationId = self.investigation_id
        if self.toolName is None:
            self.toolName = self.tool_name
        if self.evidenceId is None:
            self.evidenceId = self.evidence_id
        return self
