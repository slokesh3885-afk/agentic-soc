from typing import Dict, List, Optional, Any
from app.tools.base import SecurityTool
from app.tools.siem import SiemSearchTool
from app.tools.edr import EdrProcessSearchTool
from app.tools.hash_lookup import HashLookupTool
from app.tools.sandbox import SandboxSummaryTool
from app.tools.whois import WhoisLookupTool
from app.tools.yara import YaraScanTool


class ToolRegistry:
    """
    Central, tamper-proof security tool registry.
    Strictly allow-lists registered security tools and blocks all unauthorized
    system commands, shell executions, or arbitrary code execution attempts.
    """

    _tools: Dict[str, SecurityTool] = {}

    @classmethod
    def initialize(cls) -> None:
        """Initialize the static allow-list of approved security tools."""
        cls._tools.clear()
        tools_list: List[SecurityTool] = [
            SiemSearchTool(),
            EdrProcessSearchTool(),
            HashLookupTool(),
            SandboxSummaryTool(),
            WhoisLookupTool(),
            YaraScanTool(),
        ]
        for tool in tools_list:
            cls._tools[tool.name] = tool

    @classmethod
    def get_tool(cls, tool_name: str) -> Optional[SecurityTool]:
        """Retrieve tool instance by name if allow-listed."""
        if not cls._tools:
            cls.initialize()
        return cls._tools.get(tool_name)

    @classmethod
    def is_allowlisted(cls, tool_name: str) -> bool:
        """Verify whether tool_name is explicitly allow-listed."""
        if not cls._tools:
            cls.initialize()
        return tool_name in cls._tools

    @classmethod
    def list_tools(cls) -> List[Dict[str, Any]]:
        """List all allow-listed tools and their schemas."""
        if not cls._tools:
            cls.initialize()
        result = []
        for name, tool in cls._tools.items():
            result.append({
                "tool_name": tool.name,
                "description": tool.description,
                "evidence_type": tool.evidence_type,
                "enabled": tool.enabled,
                "input_schema": tool.input_schema,
                "output_schema": tool.output_schema,
            })
        return sorted(result, key=lambda x: x["tool_name"])


# Auto-initialize registry upon module import
ToolRegistry.initialize()
