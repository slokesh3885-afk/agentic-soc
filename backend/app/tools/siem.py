from typing import Dict, Any
from app.tools.base import SecurityTool


class SiemSearchTool(SecurityTool):
    """
    Allow-listed SIEM search tool.
    Executes deterministic telemetry searches across normalized security event logs.
    """

    name = "siem_search"
    description = "Searches SIEM event logs for specific host activities, process executions, and security log IDs."
    evidence_type = "SIEM_LOG"
    enabled = True

    input_schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "SIEM filter query, e.g. 'host=PC-DB-TEST powershell'",
            }
        },
        "required": ["query"],
    }

    output_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "total_matches": {"type": "integer"},
            "events": {"type": "array"},
        },
    }

    def validate_input(self, input_data: Dict[str, Any]) -> None:
        super().validate_input(input_data)
        if "query" not in input_data or not isinstance(input_data["query"], str) or not input_data["query"].strip():
            raise ValueError("Parameter 'query' is required and must be a non-empty string.")

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        query = input_data["query"].strip()
        lower_query = query.lower()

        # Fixed deterministic mock dataset
        # Match PC-DB-TEST or powershell queries
        if "pc-db-test" in lower_query or "powershell" in lower_query:
            events = [
                {
                    "timestamp": "2026-09-27T16:05:00Z",
                    "host": "PC-DB-TEST",
                    "process": "powershell.exe",
                    "parent_process": "unknown_process.exe",
                    "command_line": "powershell.exe -enc JABvAD0... -ExecutionPolicy Bypass -NoProfile",
                    "event_id": "4688",
                    "user": "NT AUTHORITY\\SYSTEM",
                    "log_source": "Microsoft-Windows-Security-Auditing",
                },
                {
                    "timestamp": "2026-09-27T16:07:30Z",
                    "host": "PC-DB-TEST",
                    "process": "powershell.exe",
                    "parent_process": "unknown_process.exe",
                    "command_line": "powershell.exe -Command Test-NetConnection -ComputerName 198.51.100.42 -Port 443",
                    "event_id": "4688",
                    "user": "dbadmin",
                    "log_source": "Microsoft-Windows-Security-Auditing",
                }
            ]
        elif "srv-core" in lower_query or "kerberos" in lower_query:
            events = [
                {
                    "timestamp": "2026-09-27T12:45:00Z",
                    "host": "SRV-CORE-01",
                    "process": "lsass.exe",
                    "parent_process": "wininit.exe",
                    "command_line": "C:\\Windows\\system32\\lsass.exe",
                    "event_id": "4769",
                    "user": "svc_sql",
                    "log_source": "Active Directory Kerberos Service",
                }
            ]
        else:
            # Deterministic generic response for other queries
            events = [
                {
                    "timestamp": "2026-09-27T14:00:00Z",
                    "host": "UNKNOWN-HOST",
                    "process": "svchost.exe",
                    "parent_process": "services.exe",
                    "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
                    "event_id": "4688",
                    "user": "SYSTEM",
                    "log_source": "Mock SIEM Standard Collector",
                }
            ]

        return {
            "query": query,
            "total_matches": len(events),
            "events": events,
        }
