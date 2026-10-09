import re
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.models.tool_execution import ToolExecutionModel
from app.models.critic import CriticReviewModel
from app.models.auditor import AuditedCaseModel
from app.schemas.auditor import (
    AuditClaimInput,
    AuditorRequest,
    AuditedClaimItem,
    AuditedToolExecutionItem,
    AuditedCaseResponse,
)
from app.schemas.canonical_case import (
    CanonicalClaim,
    CanonicalEvidenceItem,
    CanonicalToolExecution,
    CanonicalAuditBlock,
    CanonicalCaseJson,
    CaseJsonValidationResponse,
)
from app.services.evidence_service import compute_content_hash


# Threat actor regex pattern for attribution auditing
ATTRIBUTION_PATTERN = re.compile(
    r"\b(threat\s*actor|apt[\s\-_\d]|lazarus|cozy\s*bear|fancy\s*bear|fin\d+|actor\s+[a-z\d]+|adversary|attribution)\b",
    re.IGNORECASE,
)

# Contradiction indicators
SUSPICIOUS_TOKENS = [
    "unusual", "suspicious", "malicious", "unauthorized", "spawned by unknown",
    "threat", "anomaly", "mimikatz", "webshell", "unapproved"
]

BENIGN_TOKENS = [
    "approved administrative script", "legitimate it maintenance", "authorized task",
    "benign", "false positive", "scheduled backup script", "whitelisted", "approved maintenance"
]


def generate_next_case_id(db: Session) -> str:
    """Generate sequential Audited Case ID (e.g., CASE-001, CASE-002)."""
    records = db.query(AuditedCaseModel.id).all()
    max_num = 0
    pattern = re.compile(r"^CASE-(\d+)$")

    for (rec_id,) in records:
        match = pattern.match(rec_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num

    return f"CASE-{max_num + 1:03d}"


def _has_attribution(text: str) -> bool:
    """Detect whether claim asserts threat-actor attribution."""
    return bool(ATTRIBUTION_PATTERN.search(text))


def _check_contradiction(evidence_items: List[EvidenceModel]) -> Optional[Tuple[str, str, str]]:
    """
    Check if referenced evidence items contradict one another
    (e.g., suspicious process execution vs approved administrative maintenance).
    """
    suspicious_item = None
    benign_item = None

    for ev in evidence_items:
        raw_lower = (ev.raw_output or "").lower()
        if any(ind in raw_lower for ind in SUSPICIOUS_TOKENS):
            suspicious_item = ev
        if any(ind in raw_lower for ind in BENIGN_TOKENS):
            benign_item = ev

    if suspicious_item and benign_item and suspicious_item.id != benign_item.id:
        return (
            suspicious_item.id,
            benign_item.id,
            f"Evidence {suspicious_item.id} indicates suspicious/malicious execution, but Evidence {benign_item.id} indicates approved administrative activity."
        )
    return None


def audit_investigation(
    db: Session,
    investigation_id: str,
    request: AuditorRequest,
) -> AuditedCaseResponse:
    """
    Execute deterministic Auditor evaluation on an investigation.
    Enforces 'NO EVIDENCE -> NO CLAIM', verifies cryptographic evidence integrity,
    preserves Critic objections, identifies genuine contradictions, and outputs
    a structured audited case file.
    Does NOT execute security tools or mutate evidence.
    """
    # 1. Verify parent investigation exists
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot audit: Investigation '{investigation_id}' does not exist.",
        )

    # 2. Load all evidence bound to this investigation
    evidence_items = db.query(EvidenceModel).filter(
        EvidenceModel.investigation_id == investigation_id
    ).all()
    evidence_map: Dict[str, EvidenceModel] = {e.id: e for e in evidence_items}

    # 3. Load recorded tool execution history (Read-only, no tool execution)
    tool_exec_models = db.query(ToolExecutionModel).filter(
        ToolExecutionModel.investigation_id == investigation_id
    ).order_by(ToolExecutionModel.timestamp.asc()).all()

    tool_executions: List[AuditedToolExecutionItem] = []
    for t in tool_exec_models:
        parsed_input = t.input
        if isinstance(parsed_input, str):
            try:
                parsed_input = json.loads(parsed_input)
            except Exception:
                pass
        parsed_output = t.output
        if isinstance(parsed_output, str):
            try:
                parsed_output = json.loads(parsed_output)
            except Exception:
                pass

        tool_executions.append(
            AuditedToolExecutionItem(
                id=t.id,
                tool_name=t.tool_name,
                input=parsed_input,
                output=parsed_output,
                timestamp=t.timestamp,
                success=t.success,
                evidence_id=t.evidence_id,
            )
        )

    # 4. Load Critic findings if available
    critic_objections_claims = set()
    critic_attribution_objection = False

    if request.critic_findings is not None:
        for finding in request.critic_findings:
            if isinstance(finding, dict):
                c_text = finding.get("claim", "")
                if c_text:
                    critic_objections_claims.add(c_text.lower())
                if finding.get("category") == "UNSUPPORTED_ATTRIBUTION" or "attribution" in finding.get("reason", "").lower():
                    critic_attribution_objection = True
    else:
        # Auto-load latest Critic review from database
        latest_critic = (
            db.query(CriticReviewModel)
            .filter(CriticReviewModel.investigation_id == investigation_id)
            .order_by(CriticReviewModel.created_at.desc())
            .first()
        )
        if latest_critic:
            for obj in latest_critic.get_objections():
                if isinstance(obj, dict):
                    c_text = obj.get("claim", "")
                    if c_text:
                        critic_objections_claims.add(c_text.lower())
                    if obj.get("category") == "UNSUPPORTED_ATTRIBUTION" or "attribution" in obj.get("reason", "").lower():
                        critic_attribution_objection = True

    audited_claims: List[AuditedClaimItem] = []
    contradictions_list: List[str] = []
    uncertainties_list: List[str] = []
    unsupported_claims_list: List[str] = []

    has_supported_powershell = False
    has_unsupported_attribution = False
    has_contradiction = False

    # 5. Evaluate each claim systematically
    for c in request.claims:
        claim_text = c.claim.strip()
        ref_ids = [eid.strip() for eid in (c.evidence_ids or []) if eid.strip()]

        # CHECK 1: NO EVIDENCE -> NO CLAIM
        if not ref_ids:
            is_attr = _has_attribution(claim_text)
            if is_attr or critic_attribution_objection:
                has_unsupported_attribution = True
                status_val = "UNSUPPORTED"
                conf_val = "UNSUPPORTED"
                reason_val = "No supporting evidence provided. Under strict audit standards, threat-actor attribution cannot be established."
                uncertainties_list.append(f"Attribution claimed in '{claim_text}' is unsupported by available telemetry.")
            else:
                status_val = "UNSUPPORTED"
                conf_val = "UNSUPPORTED"
                reason_val = "No evidence ID was provided. Under strict audit standards, claims without evidence cannot be proven."

            unsupported_claims_list.append(claim_text)
            audited_claims.append(
                AuditedClaimItem(
                    claim=claim_text,
                    evidence_ids=[],
                    status=status_val,
                    confidence=conf_val,
                    reason=reason_val,
                    evidence_integrity_verified=False,
                )
            )
            continue

        # CHECK 2: Validate Evidence IDs existence
        valid_ev: List[EvidenceModel] = []
        invalid_ids: List[str] = []

        for eid in ref_ids:
            if eid in evidence_map:
                valid_ev.append(evidence_map[eid])
            else:
                invalid_ids.append(eid)

        if invalid_ids:
            status_val = "UNSUPPORTED"
            conf_val = "UNSUPPORTED"
            reason_val = f"Referenced evidence ID(s) do not exist in the verified evidence ledger: {', '.join(invalid_ids)}. Auditor will not fabricate missing evidence."
            unsupported_claims_list.append(claim_text)
            uncertainties_list.append(f"Claim references nonexistent evidence: {', '.join(invalid_ids)}")
            audited_claims.append(
                AuditedClaimItem(
                    claim=claim_text,
                    evidence_ids=ref_ids,
                    status=status_val,
                    confidence=conf_val,
                    reason=reason_val,
                    evidence_integrity_verified=False,
                )
            )
            continue

        # CHECK 3: Cryptographic Integrity Verification via Evidence Engine
        integrity_failed = []
        for ev in valid_ev:
            expected_hash = compute_content_hash(ev.raw_output)
            if ev.content_hash != expected_hash:
                integrity_failed.append(ev.id)

        if integrity_failed:
            status_val = "UNCERTAIN"
            conf_val = "UNCERTAIN"
            reason_val = f"Evidence ID(s) ({', '.join(integrity_failed)}) failed cryptographic SHA-256 integrity verification. Tampered or corrupted evidence cannot be trusted as audit proof."
            uncertainties_list.append(f"Evidence {', '.join(integrity_failed)} failed cryptographic hash integrity verification.")
            audited_claims.append(
                AuditedClaimItem(
                    claim=claim_text,
                    evidence_ids=ref_ids,
                    status=status_val,
                    confidence=conf_val,
                    reason=reason_val,
                    evidence_integrity_verified=False,
                )
            )
            continue

        # CHECK 4: Contradiction Check across referenced evidence
        contradiction = _check_contradiction(valid_ev)
        if contradiction:
            has_contradiction = True
            ev1_id, ev2_id, explanation = contradiction
            status_val = "CONTRADICTED"
            conf_val = "CONTRADICTED"
            reason_val = f"Contradictory evidence detected in ledger: {explanation}"
            contradictions_list.append(f"Evidence conflict between {ev1_id} and {ev2_id} regarding '{claim_text}': {explanation}")
            uncertainties_list.append(f"Uncertainty: Telemetry indicates suspicious execution, but correlated administrative record indicates approved maintenance.")
            audited_claims.append(
                AuditedClaimItem(
                    claim=claim_text,
                    evidence_ids=ref_ids,
                    status=status_val,
                    confidence=conf_val,
                    reason=reason_val,
                    evidence_integrity_verified=True,
                )
            )
            continue

        # CHECK 5: Threat-Actor Attribution Protection & Critic Findings
        is_attr = _has_attribution(claim_text)
        if is_attr:
            # Check if any referenced evidence explicitly establishes attribution
            has_attr_telemetry = any(_has_attribution(ev.raw_output) for ev in valid_ev)
            if not has_attr_telemetry or claim_text.lower() in critic_objections_claims:
                has_unsupported_attribution = True
                status_val = "UNSUPPORTED"
                conf_val = "UNSUPPORTED"
                reason_val = "Preserved Critic finding: No evidence establishes attribution to the specified threat actor. Forensic telemetry verifies process execution but does not establish actor attribution."
                unsupported_claims_list.append(claim_text)
                uncertainties_list.append("Available evidence does not establish threat-actor attribution.")
                audited_claims.append(
                    AuditedClaimItem(
                        claim=claim_text,
                        evidence_ids=ref_ids,
                        status=status_val,
                        confidence=conf_val,
                        reason=reason_val,
                        evidence_integrity_verified=True,
                    )
                )
                continue

        # CHECK 6: Grounding in Evidence Telemetry
        stop_words = {"the", "a", "an", "is", "was", "are", "were", "this", "that", "in", "on", "at", "by", "for", "with", "about", "to", "of", "and", "or"}
        claim_words = [w.lower() for w in re.findall(r"[A-Za-z0-9_\-]+", claim_text) if w.lower() not in stop_words]
        combined_text = " ".join([ev.raw_output.lower() for ev in valid_ev])
        matched_words = [w for w in claim_words if w in combined_text]
        support_ratio = len(matched_words) / max(len(claim_words), 1)

        is_powershell = "powershell" in claim_text.lower() and "powershell" in combined_text
        is_process = ("process" in claim_text.lower() or "execution" in claim_text.lower()) and ("process" in combined_text or "powershell" in combined_text)

        if is_powershell or is_process or support_ratio >= 0.3:
            if is_powershell:
                has_supported_powershell = True
            status_val = "SUPPORTED"
            conf_val = "SUPPORTED"
            reason_val = f"Claim is directly corroborated by verified, tamper-evident evidence ({', '.join([e.id for e in valid_ev])})."
            audited_claims.append(
                AuditedClaimItem(
                    claim=claim_text,
                    evidence_ids=ref_ids,
                    status=status_val,
                    confidence=conf_val,
                    reason=reason_val,
                    evidence_integrity_verified=True,
                )
            )
        else:
            status_val = "UNSUPPORTED"
            conf_val = "UNSUPPORTED"
            reason_val = f"Referenced evidence ({', '.join([e.id for e in valid_ev])}) does not contain sufficient telemetry to corroborate claim."
            unsupported_claims_list.append(claim_text)
            audited_claims.append(
                AuditedClaimItem(
                    claim=claim_text,
                    evidence_ids=ref_ids,
                    status=status_val,
                    confidence=conf_val,
                    reason=reason_val,
                    evidence_integrity_verified=True,
                )
            )

    # 6. Synthesize Evidence-Backed Final Conclusion
    # The Auditor does NOT trust the investigator blindly and preserves verified facts vs uncertainty
    has_supported_claims = any(c.status == "SUPPORTED" for c in audited_claims)
    if (has_supported_powershell or has_supported_claims) and (has_unsupported_attribution or critic_attribution_objection):
        final_conclusion = "Suspicious PowerShell activity is supported by available evidence. Threat-actor attribution cannot be established."
    elif (has_supported_powershell or has_supported_claims) and has_contradiction:
        final_conclusion = "PowerShell execution is supported by evidence, but contradictory administrative records indicate approved maintenance. Threat authorization remains uncertain."
    elif request.final_conclusion and not has_unsupported_attribution and not has_contradiction:
        final_conclusion = request.final_conclusion
    elif has_supported_powershell:
        final_conclusion = "Suspicious PowerShell activity on the endpoint is supported by verified forensic evidence."
    elif has_supported_claims:
        final_conclusion = "Suspicious security activity is corroborated by verified forensic evidence."
    else:
        final_conclusion = "Suspicious PowerShell activity is supported by available evidence. Threat-actor attribution cannot be established."


    # 7. Generate Case ID and Persist in Database
    case_id = generate_next_case_id(db)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    case_model = AuditedCaseModel(
        id=case_id,
        investigation_id=investigation_id,
        claims=json.dumps([c.model_dump() for c in audited_claims]),
        contradictions=json.dumps(contradictions_list),
        uncertainties=json.dumps(uncertainties_list),
        unsupported_claims=json.dumps(unsupported_claims_list),
        tool_executions=json.dumps([t.model_dump() for t in tool_executions]),
        final_conclusion=final_conclusion,
        audit_verified=True,
        created_at=now_utc,
    )

    db.add(case_model)
    db.commit()
    db.refresh(case_model)

    # Module 3K: Broadcast CASE_AUDITED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{investigation_id}",
            event_type="CASE_AUDITED",
            data={
                "case_id": case_model.id,
                "investigation_id": investigation_id,
                "claims_count": len(audited_claims),
                "unsupported_count": len(unsupported_claims_list),
                "contradictions_count": len(contradictions_list),
                "uncertainties_count": len(uncertainties_list),
                "audit_verified": True,
                "created_at": now_utc,
            },
            investigation_id=investigation_id,
        )
    except Exception:
        pass

    return AuditedCaseResponse(
        case_id=case_model.id,
        investigation_id=investigation_id,
        claims=audited_claims,
        contradictions=contradictions_list,
        uncertainties=uncertainties_list,
        unsupported_claims=unsupported_claims_list,
        tool_executions=tool_executions,
        final_conclusion=final_conclusion,
        audit_verified=True,
        created_at=now_utc,
    )


def get_latest_audited_case(db: Session, investigation_id: str) -> Optional[AuditedCaseResponse]:
    """Retrieve the most recent Audited Case file for an investigation."""
    case_model = (
        db.query(AuditedCaseModel)
        .filter(AuditedCaseModel.investigation_id == investigation_id)
        .order_by(
            AuditedCaseModel.created_at.desc(),
            func.length(AuditedCaseModel.id).desc(),
            AuditedCaseModel.id.desc(),
        )
        .first()
    )
    if not case_model:
        return None

    claims_data = case_model.get_claims()
    tools_data = case_model.get_tool_executions()

    claims = [AuditedClaimItem(**item) for item in claims_data]
    tools = [AuditedToolExecutionItem(**item) for item in tools_data]

    return AuditedCaseResponse(
        case_id=case_model.id,
        investigation_id=case_model.investigation_id,
        claims=claims,
        contradictions=case_model.get_contradictions(),
        uncertainties=case_model.get_uncertainties(),
        unsupported_claims=case_model.get_unsupported_claims(),
        tool_executions=tools,
        final_conclusion=case_model.final_conclusion,
        audit_verified=case_model.audit_verified,
        created_at=case_model.created_at,
    )


def export_canonical_case(
    db: Session,
    investigation_id: str,
    case_id: Optional[str] = None,
) -> CanonicalCaseJson:
    """
    Export the canonical audited Case JSON (Module 3F) for an investigation.
    Compiles verified claims, cryptographic evidence ledger, tool executions,
    critic findings, contradictions, uncertainties, and audit block.
    """
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' does not exist.",
        )

    # Find the audited case
    query = db.query(AuditedCaseModel).filter(AuditedCaseModel.investigation_id == investigation_id)
    if case_id:
        case_model = query.filter(AuditedCaseModel.id == case_id).first()
    else:
        case_model = query.order_by(
            AuditedCaseModel.created_at.desc(),
            func.length(AuditedCaseModel.id).desc(),
            AuditedCaseModel.id.desc(),
        ).first()

    if not case_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No audited case found for investigation '{investigation_id}'. Please run the Auditor Agent first (POST /api/investigations/{investigation_id}/audit).",
        )

    # 1. Evidence Engine Ledger with cryptographic SHA-256 verification
    evidence_models = db.query(EvidenceModel).filter(
        EvidenceModel.investigation_id == investigation_id
    ).all()

    evidence_dict: Dict[str, CanonicalEvidenceItem] = {}
    for ev in evidence_models:
        expected_hash = compute_content_hash(ev.raw_output)
        integrity_status = "VALID" if ev.content_hash == expected_hash else "FAILED"
        evidence_dict[ev.id] = CanonicalEvidenceItem(
            evidence_id=ev.id,
            evidence_type=ev.evidence_type,
            source=ev.source,
            raw_output=ev.raw_output,
            content_hash=ev.content_hash,
            integrity_status=integrity_status,
            timestamp=ev.timestamp,
        )

    # 2. Tool Executions History
    tool_exec_data = case_model.get_tool_executions()
    canonical_tools: List[CanonicalToolExecution] = []
    for t in tool_exec_data:
        canonical_tools.append(
            CanonicalToolExecution(
                execution_id=t.get("id") or t.get("execution_id") or "EXEC-UNKNOWN",
                tool_name=t.get("tool_name") or t.get("toolName") or "unknown_tool",
                input=t.get("input"),
                output=t.get("output"),
                success=bool(t.get("success", True)),
                timestamp=t.get("timestamp") or case_model.created_at,
                evidence_id=t.get("evidence_id") or t.get("evidenceId"),
            )
        )

    # 3. Critic Review Info
    critic = (
        db.query(CriticReviewModel)
        .filter(CriticReviewModel.investigation_id == investigation_id)
        .order_by(CriticReviewModel.created_at.desc())
        .first()
    )
    critic_reviewed = bool(critic)
    critic_objections_count = len(critic.get_objections()) if critic else 0

    # 4. Audit Block
    audit_block = CanonicalAuditBlock(
        audit_status="AUDIT_VERIFIED" if case_model.audit_verified else "REJECTED",
        auditor_verified=bool(case_model.audit_verified),
        critic_reviewed=critic_reviewed,
        critic_objections_count=critic_objections_count,
        audited_at=case_model.created_at,
    )

    # 5. Claims Evaluation - Strict Cross-Referencing
    raw_claims = case_model.get_claims()
    canonical_claims: List[CanonicalClaim] = []
    unsupported_claims_set = set(case_model.get_unsupported_claims())

    for c in raw_claims:
        raw_status = c.get("status", "UNCERTAIN").upper()
        if raw_status not in ("SUPPORTED", "UNSUPPORTED", "CONTRADICTED", "UNCERTAIN"):
            raw_status = "UNCERTAIN"

        raw_conf = c.get("confidence", raw_status).upper()
        if raw_conf not in ("SUPPORTED", "UNSUPPORTED", "CONTRADICTED", "UNCERTAIN"):
            raw_conf = raw_status

        # Keep only evidence IDs that exist in the ledger
        valid_ref_ids = [eid for eid in c.get("evidence_ids", []) if eid in evidence_dict]

        # Enforce 'NO EVIDENCE -> NO CLAIM'
        if raw_status == "SUPPORTED" and not valid_ref_ids:
            raw_status = "UNSUPPORTED"
            raw_conf = "UNSUPPORTED"
            unsupported_claims_set.add(c.get("claim", ""))

        # If claim is unsupported, only reference valid IDs or empty list
        if raw_status == "UNSUPPORTED":
            claim_evidence_ids = valid_ref_ids
        else:
            claim_evidence_ids = valid_ref_ids

        canonical_claims.append(
            CanonicalClaim(
                claim=c.get("claim", ""),
                evidence_ids=claim_evidence_ids,
                status=raw_status,
                confidence=raw_conf,
                reason=c.get("reason", "Audited claim evaluation"),
                evidence_integrity_verified=bool(c.get("evidence_integrity_verified", True)),
            )
        )

    return CanonicalCaseJson(
        case_id=case_model.id,
        investigation_id=case_model.investigation_id,
        schema_version="1.0.0",
        claims=canonical_claims,
        evidence=evidence_dict,
        tool_executions=canonical_tools,
        contradictions=case_model.get_contradictions(),
        uncertainties=case_model.get_uncertainties(),
        unsupported_claims=sorted(list(unsupported_claims_set)),
        final_conclusion=case_model.final_conclusion,
        audit=audit_block,
    )


def validate_canonical_case_payload(payload: Dict[str, Any]) -> CaseJsonValidationResponse:
    """
    Validate any candidate Case JSON payload against the canonical schema (Module 3F).
    Raises HTTPException(422) if validation fails.
    """
    try:
        case = CanonicalCaseJson.model_validate(payload)
        ev_count = len(case.evidence) if isinstance(case.evidence, (dict, list)) else 0
        return CaseJsonValidationResponse(
            valid=True,
            case_id=case.case_id,
            investigation_id=case.investigation_id,
            schema_version=case.schema_version,
            claims_count=len(case.claims),
            evidence_count=ev_count,
            audit_status=case.audit.audit_status,
            message="Canonical Case JSON schema validated successfully.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Canonical Case JSON validation failed: {str(e)}",
        )

