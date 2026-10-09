from typing import Dict, Any
from app.tools.base import SecurityTool


class EdrProcessSearchTool(SecurityTool):
    """
    Allow-listed EDR Process Search tool.
    Retrieves deterministic process trees, parent-child relationships, and execution metadata.
    """

    name = "edr_process_search"
    description = "Queries endpoint detection sensors for detailed process lineage trees and execution telemetry on a host."
    evidence_type = "PROCESS_EVENT"
    enabled = True

    input_schema = {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Target endpoint hostname, e.g. 'PC-DB-TEST'",
            }
        },
        "required": ["host"],
    }

    output_schema = {
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "lineage_summary": {"type": "string"},
            "processes": {"type": "array"},
        },
    }

    def validate_input(self, input_data: Dict[str, Any]) -> None:
        super().validate_input(input_data)
        if "host" not in input_data or not isinstance(input_data["host"], str) or not input_data["host"].strip():
            raise ValueError("Parameter 'host' is required and must be a valid non-empty string.")

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        host = input_data["host"].strip().upper()

        if host == "PC-DB-TEST":
            processes = [
                {
                    "process": "winword.exe",
                    "parent": "explorer.exe",
                    "pid": 4812,
                    "parent_pid": 2100,
                    "command_line": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\dbadmin\\Downloads\\Invoice_Q3.docm"',
                    "timestamp": "2026-09-27T16:04:12Z",
                    "user": "PC-DB-TEST\\dbadmin",
                },
                {
                    "process": "powershell.exe",
                    "parent": "winword.exe",
                    "pid": 5920,
                    "parent_pid": 4812,
                    "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc JABvAD0... -WindowStyle Hidden",
                    "timestamp": "2026-09-27T16:05:00Z",
                    "user": "PC-DB-TEST\\dbadmin",
                },
                {
                    "process": "cmd.exe",
                    "parent": "powershell.exe",
                    "pid": 6312,
                    "parent_pid": 5920,
                    "command_line": "cmd.exe /c whoami /priv > C:\\Users\\dbadmin\\AppData\\Local\\Temp\\out.txt",
                    "timestamp": "2026-09-27T16:05:45Z",
                    "user": "PC-DB-TEST\\dbadmin",
                }
            ]
            summary = "winword.exe (PID 4812) -> powershell.exe (PID 5920) -> cmd.exe (PID 6312)"
        else:
            processes = [
                {
                    "process": "explorer.exe",
                    "parent": "userinit.exe",
                    "pid": 1840,
                    "parent_pid": 1120,
                    "command_line": "C:\\Windows\\explorer.exe",
                    "timestamp": "2026-09-27T08:00:00Z",
                    "user": f"{host}\\standard_user",
                }
            ]
            summary = "explorer.exe (PID 1840) [Standard baseline process]"

        return {
            "host": host,
            "lineage_summary": summary,
            "total_processes": len(processes),
            "processes": processes,
        }
