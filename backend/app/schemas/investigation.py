import json
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, model_validator


class InvestigationCreate(BaseModel):
    """Schema for creating a new investigation."""
    alert_name: str
    target_host: str
    severity: str
    event_timestamp: str
    description: Optional[str] = ""
    status: Optional[str] = "Investigating"
    evidence_count: Optional[int] = 0
    trust_score: Optional[int] = 91

    @model_validator(mode="before")
    @classmethod
    def map_aliases_and_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Normalize camelCase and frontend aliases to snake_case schema fields
            if "alert_name" not in data and "alertName" in data:
                data["alert_name"] = data["alertName"]
            elif "alert_name" not in data and "alert" in data:
                data["alert_name"] = data["alert"]

            if "target_host" not in data and "targetHost" in data:
                data["target_host"] = data["targetHost"]
            elif "target_host" not in data and "host" in data:
                data["target_host"] = data["host"]

            if "event_timestamp" not in data and "eventTimestamp" in data:
                data["event_timestamp"] = data["eventTimestamp"]
            elif "event_timestamp" not in data and "timestamp" in data:
                data["event_timestamp"] = data["timestamp"]

            if "evidence_count" not in data and "evidenceCount" in data:
                data["evidence_count"] = data["evidenceCount"]
            elif "evidence_count" not in data and "artifactCount" in data:
                data["evidence_count"] = data["artifactCount"]

            if "trust_score" not in data and "trustScore" in data:
                data["trust_score"] = data["trustScore"]
            elif "trust_score" not in data and "evidenceTrustScore" in data:
                data["trust_score"] = data["evidenceTrustScore"]

        return data


class InvestigationResponse(BaseModel):
    """Schema for investigation responses matching both backend and frontend contracts."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_name: str
    target_host: str
    severity: str
    event_timestamp: str
    description: Optional[str] = ""
    status: str = "Investigating"
    evidence_count: int = 0
    trust_score: int = 90
    created_at: str
    assigned_agent: Optional[str] = "Host Triage Agent"
    mitre_technique: Optional[str] = ""
    evidence_corroboration: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    # Convenience aliases for direct React compatibility
    alert: Optional[str] = None
    host: Optional[str] = None
    evidenceTrustScore: Optional[int] = None
    started: Optional[str] = None
    eventTimestamp: Optional[str] = None
    createdTimestamp: Optional[str] = None
    artifactCount: Optional[int] = None

    @model_validator(mode="after")
    def populate_frontend_aliases(self) -> "InvestigationResponse":
        if self.alert is None:
            self.alert = self.alert_name
        if self.host is None:
            self.host = self.target_host
        if self.evidenceTrustScore is None:
            self.evidenceTrustScore = self.trust_score
        if self.eventTimestamp is None:
            self.eventTimestamp = self.event_timestamp
        if self.createdTimestamp is None:
            self.createdTimestamp = self.created_at
        if self.artifactCount is None:
            self.artifactCount = self.evidence_count
        if self.started is None:
            self.started = self.created_at
        return self
