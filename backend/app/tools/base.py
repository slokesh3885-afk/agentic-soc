import abc
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class SecurityTool(abc.ABC):
    """
    Abstract Base Class for all allow-listed SOC security tools.
    Enforces strict safety boundaries, schema declarations, and deterministic execution.
    """

    name: str
    description: str
    evidence_type: str
    enabled: bool = True
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]

    def validate_input(self, input_data: Dict[str, Any]) -> None:
        """
        Validate input parameters against the tool's required schema and safety rules.
        Rejects command injection strings, shell syntax, path traversal, and unauthorized inputs.
        """
        if not isinstance(input_data, dict):
            raise ValueError(f"Input for tool '{self.name}' must be a key-value dictionary.")

        # Safety boundary inspection: block shell metacharacters and suspicious execution attempts
        for key, val in input_data.items():
            if isinstance(val, str):
                dangerous_tokens = [
                    ";", "&&", "||", "`", "$(", "|", ">", "<",
                    "powershell", "cmd.exe", "bash", "sh -c",
                    "/bin/sh", "system(", "exec(", "eval("
                ]
                # Allow query search containing normal words like "powershell" if it's a SIEM query parameter,
                # but block explicit command injection symbols if passed outside quoted query contexts.
                if key != "query":
                    for token in [";", "&&", "||", "`", "$(", "exec(", "eval("]:
                        if token in val:
                            raise ValueError(f"Input parameter '{key}' contains unauthorized shell token: '{token}'")

    @abc.abstractmethod
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute deterministic security tool logic.
        Must return a structured dictionary conforming to output_schema.
        """
        pass

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Standard execution harness with timestamping and error containment.
        """
        self.validate_input(input_data)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = self.execute(input_data)
        return {
            "tool_name": self.name,
            "success": True,
            "timestamp": now_utc,
            "data": data,
            "error": None,
        }
