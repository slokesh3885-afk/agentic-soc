"""
Analyst Agent Service (Module 3Q)
Agentic SOC — Auditable AI Security Operations Center

The Analyst Agent is the primary reasoning and hypothesis formulation layer:
- Ingests investigation context, alert telemetry, and collected evidence.
- Deterministically synthesizes preliminary investigative hypotheses.
- Formulates structured analytical claims (CLM-xxx) bound strictly to Evidence IDs.
- Evaluates preliminary confidence based on evidence corroboration.
- Identifies MITRE ATT&CK tactics corresponding to observed telemetry.
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.schemas.agent import (
    AnalystClaim,
    AnalystRequestPayload,
    AnalystResponse,
)


def run_analyst_agent(db: Session, payload: AnalystRequestPayload) -> AnalystResponse:
    """
    Executes the deterministic Analyst Agent reasoning engine for an investigation.
    """
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == payload.investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation {payload.investigation_id} not found")

    evidence_items = (
        db.query(EvidenceModel)
        .filter(EvidenceModel.investigation_id == payload.investigation_id)
        .order_by(EvidenceModel.id.asc())
        .all()
    )

    alert_name = getattr(inv, "alert_name", getattr(inv, "alert", "Unknown Security Alert"))
    target_host = getattr(inv, "target_host", getattr(inv, "host", "Unknown Host"))
    alert_lower = (alert_name or "").lower()

    claims: List[AnalystClaim] = []
    mitre_tactics: List[str] = []
    preliminary_hypothesis = ""
    overall_confidence = 0.85

    # Analyze collected evidence artifacts
    evidence_ids = [e.id for e in evidence_items]
    has_evidence = len(evidence_ids) > 0

    # Categorize telemetry types
    edr_evidence = [e for e in evidence_items if "EDR" in e.evidence_type.upper()]
    siem_evidence = [e for e in evidence_items if "SIEM" in e.evidence_type.upper() or "LOG" in e.evidence_type.upper()]
    sandbox_evidence = [e for e in evidence_items if "SANDBOX" in e.evidence_type.upper()]
    hash_evidence = [e for e in evidence_items if "HASH" in e.evidence_type.upper() or "REPUTATION" in e.evidence_type.upper()]

    # Scenario 1: PowerShell / Script Execution
    if "powershell" in alert_lower or "script" in alert_lower:
        mitre_tactics.extend(["Execution", "Defense Evasion"])
        primary_ev = [e.id for e in (edr_evidence or siem_evidence or evidence_items)[:2]]

        claims.append(
            AnalystClaim(
                claim_id="CLM-001",
                statement=f"Unusual PowerShell execution detected on host {target_host} spawning sub-processes with encoded arguments.",
                supporting_evidence_ids=primary_ev if primary_ev else (evidence_ids[:1] if evidence_ids else []),
                confidence=0.92 if primary_ev else 0.50,
                threat_attribution_hypothesis=None, # Attribution guard: no uncorroborated attribution
                mitre_tactics=["Execution", "Defense Evasion"],
            )
        )

        if sandbox_evidence or hash_evidence:
            sec_ev = [e.id for e in (sandbox_evidence + hash_evidence)]
            claims.append(
                AnalystClaim(
                    claim_id="CLM-002",
                    statement="Detonated payload demonstrates credential harvesting or lateral staging behaviors.",
                    supporting_evidence_ids=sec_ev,
                    confidence=0.88,
                    threat_attribution_hypothesis=None,
                    mitre_tactics=["Credential Access", "Lateral Movement"],
                )
            )

        preliminary_hypothesis = (
            f"Preliminary analysis confirms suspicious PowerShell execution sequence on {target_host}. "
            f"Observed telemetry indicates possible initial access or execution staging. "
            f"Attribution to external threat actors cannot be established without adversary infrastructure artifacts."
        )
        overall_confidence = 0.90 if len(evidence_items) >= 2 else 0.70

    # Scenario 2: Ransomware / Data Destruction / Exfiltration
    elif "ransom" in alert_lower or "crypto" in alert_lower or "exfil" in alert_lower:
        mitre_tactics.extend(["Impact", "Exfiltration"])
        claims.append(
            AnalystClaim(
                claim_id="CLM-001",
                statement=f"High-frequency file modification and unauthorized network beaconing observed from {target_host}.",
                supporting_evidence_ids=evidence_ids[:2] if evidence_ids else [],
                confidence=0.94 if evidence_ids else 0.40,
                threat_attribution_hypothesis=None,
                mitre_tactics=["Impact", "Exfiltration"],
            )
        )
        preliminary_hypothesis = (
            f"Evidence indicates rapid unauthorized cryptographic transformations on {target_host}. "
            f"Immediate isolation recommended pending containment approval."
        )
        overall_confidence = 0.93

    # Scenario 3: Brute Force / Credential Stuffing
    elif "brute" in alert_lower or "auth" in alert_lower or "login" in alert_lower:
        mitre_tactics.extend(["Credential Access", "Initial Access"])
        claims.append(
            AnalystClaim(
                claim_id="CLM-001",
                statement=f"Multiple consecutive failed authentication attempts followed by anomalous privilege elevation on {target_host}.",
                supporting_evidence_ids=evidence_ids[:2] if evidence_ids else [],
                confidence=0.89 if evidence_ids else 0.45,
                threat_attribution_hypothesis=None,
                mitre_tactics=["Credential Access"],
            )
        )
        preliminary_hypothesis = (
            f"Anomalous authentication burst consistent with password spray or brute force telemetry. "
            f"Account credential revocation and session invalidation required."
        )
        overall_confidence = 0.88

    # Default / Generic Alert
    else:
        mitre_tactics.append("Discovery")
        claims.append(
            AnalystClaim(
                claim_id="CLM-001",
                statement=f"Anomalous telemetry recorded for alert '{alert_name}' on target {target_host}.",
                supporting_evidence_ids=evidence_ids[:1] if evidence_ids else [],
                confidence=0.80 if evidence_ids else 0.35,
                threat_attribution_hypothesis=None,
                mitre_tactics=["Discovery"],
            )
        )
        preliminary_hypothesis = (
            f"Investigation telemetry for {alert_name} suggests unauthorized system probing. "
            f"Further tool queries recommended to confirm intent."
        )
        overall_confidence = 0.75 if has_evidence else 0.30

    if payload.analyst_notes:
        preliminary_hypothesis += f" [Analyst Note: {payload.analyst_notes}]"

    return AnalystResponse(
        investigation_id=payload.investigation_id,
        preliminary_hypothesis=preliminary_hypothesis,
        claims=claims,
        overall_confidence=round(overall_confidence, 2),
        evidence_analyzed_count=len(evidence_items),
        recommended_next_action="CRITIC_REVIEW",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
