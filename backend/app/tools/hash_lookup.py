import re
from typing import Dict, Any
from app.tools.base import SecurityTool


class HashLookupTool(SecurityTool):
    """
    Allow-listed File & Artifact Hash Lookup tool.
    Queries deterministic mock threat intelligence feeds for reputation, first seen, and malware families.
    Enforces the rule: Never claim a hash is malicious unless the mock dataset explicitly flags it.
    """

    name = "hash_lookup"
    description = "Queries threat intelligence databases for file hash reputation, signatures, and known malware associations."
    evidence_type = "HASH_LOOKUP"
    enabled = True

    input_schema = {
        "type": "object",
        "properties": {
            "hash": {
                "type": "string",
                "description": "Cryptographic hash (MD5, SHA-1, or SHA-256 hex string)",
            }
        },
        "required": ["hash"],
    }

    output_schema = {
        "type": "object",
        "properties": {
            "hash": {"type": "string"},
            "hash_type": {"type": "string"},
            "reputation": {"type": "string"},
            "first_seen": {"type": "string"},
            "malware_family": {"type": "string", "nullable": True},
            "sources_checked": {"type": "array"},
        },
    }

    # Deterministic mock threat intelligence knowledge base
    MOCK_HASH_DATABASE = {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
            "reputation": "UNKNOWN",
            "first_seen": "2026-09-20T08:15:30Z",
            "malware_family": None,
            "threat_score": 0,
            "sources_checked": ["Mock Threat Intel"],
        },
        "44d88612fea8a8f36de82e1278abb02f": {
            "reputation": "MALICIOUS",
            "first_seen": "2025-11-12T14:22:10Z",
            "malware_family": "CobaltStrike.Beacon",
            "threat_score": 98,
            "sources_checked": ["Mock Threat Intel", "Mock Malware Feed", "Mock EDR Cloud"],
        },
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9": {
            "reputation": "BENIGN",
            "first_seen": "2024-01-10T00:00:00Z",
            "malware_family": None,
            "threat_score": 0,
            "sources_checked": ["Mock Threat Intel", "Microsoft Known Good Cache"],
        }
    }

    def validate_input(self, input_data: Dict[str, Any]) -> None:
        super().validate_input(input_data)
        if "hash" not in input_data or not isinstance(input_data["hash"], str) or not input_data["hash"].strip():
            raise ValueError("Parameter 'hash' is required and must be a valid hex string.")

        clean_hash = input_data["hash"].strip().lower()
        if not re.match(r"^[a-f0-9]{32,64}$", clean_hash):
            raise ValueError("Parameter 'hash' must be a valid MD5, SHA-1, or SHA-256 hexadecimal string.")

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        clean_hash = input_data["hash"].strip().lower()

        # Identify hash algorithm by length
        hash_type = "SHA-256" if len(clean_hash) == 64 else ("SHA-1" if len(clean_hash) == 40 else "MD5")

        if clean_hash in self.MOCK_HASH_DATABASE:
            entry = self.MOCK_HASH_DATABASE[clean_hash]
            return {
                "hash": clean_hash,
                "hash_type": hash_type,
                "reputation": entry["reputation"],
                "first_seen": entry["first_seen"],
                "malware_family": entry["malware_family"],
                "sources_checked": entry["sources_checked"],
            }

        # Any uncatalogued hash strictly defaults to UNKNOWN
        return {
            "hash": clean_hash,
            "hash_type": hash_type,
            "reputation": "UNKNOWN",
            "first_seen": "2026-09-01T00:00:00Z",
            "malware_family": None,
            "sources_checked": ["Mock Threat Intel"],
        }
