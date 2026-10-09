from typing import Dict, Any
from app.tools.base import SecurityTool


class SandboxSummaryTool(SecurityTool):
    """
    Allow-listed Automated Malware Sandbox Analysis Summary tool.
    Returns deterministic detonated artifact behavior, network telemetry, files dropped, and verdicts.
    """

    name = "sandbox_summary"
    description = "Retrieves behavioral sandbox detonation telemetry for analyzed binary samples or scripts."
    evidence_type = "SANDBOX_RESULT"
    enabled = True

    input_schema = {
        "type": "object",
        "properties": {
            "sample_id": {
                "type": "string",
                "description": "Identifier of the analyzed sample, e.g. 'sample-001'",
            }
        },
        "required": ["sample_id"],
    }

    output_schema = {
        "type": "object",
        "properties": {
            "sample_id": {"type": "string"},
            "verdict": {"type": "string"},
            "execution_behavior": {"type": "array"},
            "network_connections": {"type": "array"},
            "files_created": {"type": "array"},
            "registry_activity": {"type": "array"},
            "processes": {"type": "array"},
        },
    }

    MOCK_SAMPLES = {
        "sample-001": {
            "verdict": "SUSPICIOUS",
            "execution_behavior": [
                "Process hollowing attempt detected",
                "Suspicious child process spawned from Office application",
                "Base64 encoded command line executed via powershell.exe",
                "Evasion technique: WindowStyle Hidden",
            ],
            "network_connections": [
                {
                    "ip": "198.51.100.42",
                    "port": 443,
                    "protocol": "TCP",
                    "domain": "suspicious-c2-tunnel.biz",
                    "bytes_sent": 482,
                    "bytes_received": 1420,
                }
            ],
            "files_created": [
                "C:\\Users\\dbadmin\\AppData\\Local\\Temp\\Invoice_Q3.docm",
                "C:\\Users\\dbadmin\\AppData\\Local\\Temp\\stage2.ps1",
                "C:\\Users\\dbadmin\\AppData\\Local\\Temp\\out.txt",
            ],
            "registry_activity": [
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsTelemetryUpdate",
                "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\VBAWarnings = 1",
            ],
            "processes": [
                "winword.exe (PID: 4812)",
                "powershell.exe (PID: 5920)",
                "cmd.exe (PID: 6312)",
            ],
        },
        "sample-002": {
            "verdict": "BENIGN",
            "execution_behavior": [
                "Clean execution without privilege escalation",
                "Digital signature validated against trusted root",
            ],
            "network_connections": [],
            "files_created": ["C:\\ProgramData\\Application\\log.txt"],
            "registry_activity": [],
            "processes": ["updater.exe (PID: 2410)"],
        }
    }

    def validate_input(self, input_data: Dict[str, Any]) -> None:
        super().validate_input(input_data)
        if "sample_id" not in input_data or not isinstance(input_data["sample_id"], str) or not input_data["sample_id"].strip():
            raise ValueError("Parameter 'sample_id' is required and must be a non-empty string.")

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        sample_id = input_data["sample_id"].strip().lower()

        if sample_id in self.MOCK_SAMPLES:
            data = self.MOCK_SAMPLES[sample_id]
            return {
                "sample_id": sample_id,
                **data
            }

        # Default fallback for unknown sample IDs
        return {
            "sample_id": sample_id,
            "verdict": "UNKNOWN",
            "execution_behavior": ["Sample not found in active detonation pool."],
            "network_connections": [],
            "files_created": [],
            "registry_activity": [],
            "processes": [],
        }
