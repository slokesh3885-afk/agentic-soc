from typing import Dict, Any
from app.tools.base import SecurityTool


class WhoisLookupTool(SecurityTool):
    """
    Allow-listed Domain WHOIS Registration Lookup tool.
    Returns deterministic registration metadata without making live network requests.
    """

    name = "whois_lookup"
    description = "Queries domain registration details, registrar, nameservers, and creation/expiration dates."
    evidence_type = "WHOIS_RESULT"
    enabled = True

    input_schema = {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "Fully Qualified Domain Name, e.g. 'example.test' or 'suspicious-c2-tunnel.biz'",
            }
        },
        "required": ["domain"],
    }

    output_schema = {
        "type": "object",
        "properties": {
            "domain": {"type": "string"},
            "registrar": {"type": "string"},
            "creation_date": {"type": "string"},
            "expiration_date": {"type": "string"},
            "nameservers": {"type": "array"},
            "status": {"type": "array"},
            "registrant_country": {"type": "string"},
        },
    }

    MOCK_DOMAINS = {
        "example.test": {
            "registrar": "Mock Registrar LLC (IANA-999)",
            "creation_date": "2026-08-15T12:00:00Z",
            "expiration_date": "2027-08-15T12:00:00Z",
            "nameservers": ["ns1.mockdns.org", "ns2.mockdns.org"],
            "status": ["clientTransferProhibited", "active"],
            "registrant_country": "US",
        },
        "suspicious-c2-tunnel.biz": {
            "registrar": "Bulletproof Offshore Domains Inc.",
            "creation_date": "2026-09-25T03:14:22Z",
            "expiration_date": "2027-09-25T03:14:22Z",
            "nameservers": ["ns1.anonymous-c2-host.cc", "ns2.anonymous-c2-host.cc"],
            "status": ["clientTransferProhibited", "clientDeleteProhibited"],
            "registrant_country": "IS",
        },
    }

    def validate_input(self, input_data: Dict[str, Any]) -> None:
        super().validate_input(input_data)
        if "domain" not in input_data or not isinstance(input_data["domain"], str) or not input_data["domain"].strip():
            raise ValueError("Parameter 'domain' is required and must be a valid domain string.")

        domain = input_data["domain"].strip().lower()
        if "://" in domain or "/" in domain or "\\" in domain:
            raise ValueError("Parameter 'domain' must be a domain name, not a URL or path.")

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        domain = input_data["domain"].strip().lower()

        if domain in self.MOCK_DOMAINS:
            data = self.MOCK_DOMAINS[domain]
            return {
                "domain": domain,
                **data
            }

        # Deterministic generation for unknown domains
        return {
            "domain": domain,
            "registrar": "Mock Standard Registrar Group",
            "creation_date": "2025-01-01T00:00:00Z",
            "expiration_date": "2027-01-01T00:00:00Z",
            "nameservers": ["ns1.mockregistrar.net", "ns2.mockregistrar.net"],
            "status": ["active"],
            "registrant_country": "US",
        }
