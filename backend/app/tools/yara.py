from typing import Dict, Any
from app.tools.base import SecurityTool


class YaraScanTool(SecurityTool):
    """
    Allow-listed YARA Rule Signature Pattern Scanning tool.
    Matches artifacts against deterministic signature sets for known malware techniques.
    """

    name = "yara_scan"
    description = "Scans files or telemetry samples against compiled YARA rule signatures for malicious indicators."
    evidence_type = "YARA_RESULT"
    enabled = True

    input_schema = {
        "type": "object",
        "properties": {
            "sample_id": {
                "type": "string",
                "description": "Identifier of the target sample or artifact, e.g. 'sample-001'",
            }
        },
        "required": ["sample_id"],
    }

    output_schema = {
        "type": "object",
        "properties": {
            "sample_id": {"type": "string"},
            "total_matches": {"type": "integer"},
            "matches": {"type": "array"},
        },
    }

    MOCK_YARA_DATABASE = {
        "sample-001": [
            {
                "rule": "SuspiciousPowerShellEncoded",
                "severity": "HIGH",
                "description": "Detects Base64 encoded PowerShell with bypass execution policies",
                "tags": ["apt", "obfuscation", "powershell"],
                "strings_matched": ["-enc", "-EncodedCommand", "FromBase64String"],
            },
            {
                "rule": "OfficeSpawningCommandLine",
                "severity": "CRITICAL",
                "description": "Detects Microsoft Office suite binaries invoking cmd or powershell",
                "tags": ["initial_access", "macro", "execution"],
                "strings_matched": ["WINWORD.EXE", "powershell.exe"],
            }
        ],
        "sample-002": []
    }

    def validate_input(self, input_data: Dict[str, Any]) -> None:
        super().validate_input(input_data)
        if "sample_id" not in input_data or not isinstance(input_data["sample_id"], str) or not input_data["sample_id"].strip():
            raise ValueError("Parameter 'sample_id' is required and must be a non-empty string.")

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        sample_id = input_data["sample_id"].strip().lower()

        matches = self.MOCK_YARA_DATABASE.get(sample_id, [])

        return {
            "sample_id": sample_id,
            "total_matches": len(matches),
            "matches": matches,
        }
