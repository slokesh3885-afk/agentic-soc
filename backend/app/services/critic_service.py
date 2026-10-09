import re
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.models.critic import CriticReviewModel
from app.schemas.critic import (
    ClaimInput,
    CriticRequest,
    ClaimEvaluation,
    CriticObjection,
    CriticResponse,
    ClaimStatus,
    OverallCriticStatus,
)
from app.services.evidence_service import compute_content_hash

# Controlled patterns for detecting threat actor attribution claims
ATTRIBUTION_PATTERN = re.compile(
    r"\b(threat\s*actor|apt[\s\-_\d]|lazarus|cozy\s*bear|fancy\s*bear|fin\d+|actor\s+[a-z\d]+|adversary|attribution)\b",
    re.IGNORECASE,
)

# Overconfident phrasing that requires tempered security phrasing
OVERCONFIDENT_PATTERNS = [
    (re.compile(r"\bdefinitely\b", re.IGNORECASE), "definitely"),
    (re.compile(r"\bcertainly\b", re.IGNORECASE), "certainly"),
    (re.compile(r"\bconfirmed\b", re.IGNORECASE), "confirmed"),
    (re.compile(r"\bproves\b", re.IGNORECASE), "proves"),
    (re.compile(r"\b100%\s*malicious\b", re.IGNORECASE), "100% malicious"),
    (re.compile(r"\bundeniabl(?:e|y)\b", re.IGNORECASE), "undeniably"),
    (re.compile(r"\bindisputabl(?:e|y)\b", re.IGNORECASE), "indisputably"),
    (re.compile(r"\babsolute\s*certainty\b", re.IGNORECASE), "absolute certainty"),
]

# Contradiction detection keywords
SUSPICIOUS_INDICATORS = [
    "unusual", "suspicious", "malicious", "unauthorized", "spawned by unknown",
    "threat", "anomaly", "mimikatz", "webshell", "unapproved", "powershell.exe executed from an unusual parent"
]

BENIGN_INDICATORS = [
    "approved administrative script", "legitimate it maintenance", "authorized task",
    "benign", "false positive", "scheduled backup script", "whitelisted", "approved maintenance"
]


def generate_next_critic_id(db: Session) -> str:
    """Generate sequential Critic review ID (e.g., CRITIC-001)."""
    records = db.query(CriticReviewModel.id).all()
    max_num = 0
    pattern = re.compile(r"^CRITIC-(\d+)$")

    for (rec_id,) in records:
        match = pattern.match(rec_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num

    return f"CRITIC-{max_num + 1:03d}"


def _has_threat_actor_attribution(text: str) -> bool:
    """Detect whether claim asserts threat-actor attribution."""
    return bool(ATTRIBUTION_PATTERN.search(text))


def _extract_overconfident_tokens(text: str) -> List[str]:
    """Find any overconfident tokens in text."""
    found = []
    for pat, label in OVERCONFIDENT_PATTERNS:
        if pat.search(text):
            found.append(label)
    return found


def _check_evidence_contradiction(evidence_items: List[EvidenceModel]) -> Optional[Tuple[str, str, str]]:
    """
    Deterministically check if a set of evidence records contradicts itself
    (e.g., one states suspicious/malicious execution while another states approved/legitimate).
    Returns (ev1_id, ev2_id, explanation) if contradictory, else None.
    """
    suspicious_item = None
    benign_item = None

    for ev in evidence_items:
        raw_lower = (ev.raw_output or "").lower()
        if any(ind in raw_lower for ind in SUSPICIOUS_INDICATORS):
            suspicious_item = ev
        if any(ind in raw_lower for ind in BENIGN_INDICATORS):
            benign_item = ev

    if suspicious_item and benign_item and suspicious_item.id != benign_item.id:
        return (
            suspicious_item.id,
            benign_item.id,
            f"Evidence {suspicious_item.id} indicates suspicious/malicious execution, but Evidence {benign_item.id} indicates approved/legitimate administrative activity."
        )
    return None


def evaluate_draft_conclusion(
    db: Session,
    investigation_id: str,
    request: CriticRequest,
) -> CriticResponse:
    """
    Execute deterministic Critic / Red-Team evaluation on investigator draft conclusion and claims.
    Validates referenced evidence, enforces strict attribution standards, detects contradictions,
    and flags overconfidence.
    """
    # 1. Verify parent investigation exists
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot run critic: Investigation '{investigation_id}' does not exist.",
        )

    # 2. Retrieve all evidence bound to this investigation
    investigation_evidence = db.query(EvidenceModel).filter(
        EvidenceModel.investigation_id == investigation_id
    ).all()
    evidence_map: Dict[str, EvidenceModel] = {e.id: e for e in investigation_evidence}

    evaluations: List[ClaimEvaluation] = []
    objections: List[CriticObjection] = []
    missing_evidence_list: List[str] = []
    contradictions_list: List[str] = []
    overclaims_list: List[str] = []

    # 3. Evaluate each claim submitted
    for c in request.claims:
        claim_text = c.claim.strip()
        ref_ids = [eid.strip() for eid in (c.evidence_ids or []) if eid.strip()]

        # CHECK 1: Empty Evidence List
        if not ref_ids:
            is_attribution = _has_threat_actor_attribution(claim_text)
            if is_attribution:
                reason = "No evidence ID establishes attribution to the specified threat actor."
                evaluations.append(
                    ClaimEvaluation(
                        claim=claim_text,
                        status=ClaimStatus.UNSUPPORTED.value,
                        reason=reason,
                        evidence_ids=[],
                        valid_evidence_ids=[],
                        invalid_evidence_ids=[],
                    )
                )
                objections.append(
                    CriticObjection(
                        claim=claim_text,
                        status=ClaimStatus.UNSUPPORTED.value,
                        reason=reason,
                        evidence_ids=[],
                        category="UNSUPPORTED_ATTRIBUTION",
                    )
                )
                missing_evidence_list.append("Evidence linking the observed activity to the specified threat actor")
                overclaims_list.append("Threat-actor attribution exceeds the available evidence.")
            else:
                reason = "No evidence ID was provided to support this claim."
                evaluations.append(
                    ClaimEvaluation(
                        claim=claim_text,
                        status=ClaimStatus.UNSUPPORTED.value,
                        reason=reason,
                        evidence_ids=[],
                        valid_evidence_ids=[],
                        invalid_evidence_ids=[],
                    )
                )
                objections.append(
                    CriticObjection(
                        claim=claim_text,
                        status=ClaimStatus.UNSUPPORTED.value,
                        reason=reason,
                        evidence_ids=[],
                        category="MISSING_EVIDENCE",
                    )
                )
                missing_evidence_list.append(f"Supporting evidence for claim: '{claim_text}'")
            continue

        # CHECK 2: Validate Evidence IDs existence
        valid_evidence: List[EvidenceModel] = []
        invalid_ids: List[str] = []

        for eid in ref_ids:
            if eid in evidence_map:
                valid_evidence.append(evidence_map[eid])
            else:
                invalid_ids.append(eid)

        valid_ids = [e.id for e in valid_evidence]

        if invalid_ids:
            reason = f"Referenced evidence ID(s) do not exist for this investigation: {', '.join(invalid_ids)}."
            evaluations.append(
                ClaimEvaluation(
                    claim=claim_text,
                    status=ClaimStatus.INVALID_EVIDENCE_REFERENCE.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    valid_evidence_ids=valid_ids,
                    invalid_evidence_ids=invalid_ids,
                )
            )
            objections.append(
                CriticObjection(
                    claim=claim_text,
                    status=ClaimStatus.INVALID_EVIDENCE_REFERENCE.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    category="INVALID_EVIDENCE",
                )
            )
            missing_evidence_list.append(f"Valid evidence record for {', '.join(invalid_ids)}")
            continue

        # CHECK 3: Cryptographic integrity check on valid evidence
        integrity_failed_ids = []
        for ev in valid_evidence:
            expected_hash = compute_content_hash(ev.raw_output)
            if ev.content_hash != expected_hash:
                integrity_failed_ids.append(ev.id)

        if integrity_failed_ids:
            reason = f"Evidence ID(s) failed cryptographic integrity verification: {', '.join(integrity_failed_ids)}."
            evaluations.append(
                ClaimEvaluation(
                    claim=claim_text,
                    status=ClaimStatus.UNCERTAIN.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    valid_evidence_ids=valid_ids,
                    invalid_evidence_ids=[],
                )
            )
            objections.append(
                CriticObjection(
                    claim=claim_text,
                    status=ClaimStatus.UNCERTAIN.value,
                    reason=reason,
                    evidence_ids=integrity_failed_ids,
                    category="INTEGRITY_FAILURE",
                )
            )
            continue

        # CHECK 4: Contradiction Detection across referenced evidence
        contradiction = _check_evidence_contradiction(valid_evidence)
        if contradiction:
            ev1_id, ev2_id, explanation = contradiction
            reason = f"Contradictory evidence detected: {explanation}"
            evaluations.append(
                ClaimEvaluation(
                    claim=claim_text,
                    status=ClaimStatus.CONTRADICTED.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    valid_evidence_ids=valid_ids,
                    invalid_evidence_ids=[],
                )
            )
            objections.append(
                CriticObjection(
                    claim=claim_text,
                    status=ClaimStatus.CONTRADICTED.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    category="CONTRADICTION",
                )
            )
            contradictions_list.append(
                f"Contradiction between {ev1_id} and {ev2_id} regarding '{claim_text}': {explanation}"
            )
            continue

        # CHECK 5: Threat Actor Attribution with Evidence
        # If the claim claims attribution, check if the referenced evidence explicitly establishes it
        if _has_threat_actor_attribution(claim_text):
            evidence_has_attribution = False
            for ev in valid_evidence:
                raw_lower = (ev.raw_output or "").lower()
                # Check if evidence establishes attribution
                if _has_threat_actor_attribution(raw_lower):
                    evidence_has_attribution = True
                    break

            if not evidence_has_attribution:
                reason = "No evidence establishes attribution to the specified threat actor. Referenced evidence contains process or network telemetry but lacks threat intelligence linking activity to this actor."
                evaluations.append(
                    ClaimEvaluation(
                        claim=claim_text,
                        status=ClaimStatus.UNSUPPORTED.value,
                        reason=reason,
                        evidence_ids=ref_ids,
                        valid_evidence_ids=valid_ids,
                        invalid_evidence_ids=[],
                    )
                )
                objections.append(
                    CriticObjection(
                        claim=claim_text,
                        status=ClaimStatus.UNSUPPORTED.value,
                        reason=reason,
                        evidence_ids=ref_ids,
                        category="UNSUPPORTED_ATTRIBUTION",
                    )
                )
                missing_evidence_list.append("Evidence establishing attribution linking observed telemetry to the threat actor")
                overclaims_list.append("Threat-actor attribution exceeds what the referenced evidence establishes.")
                continue

        # CHECK 6: General Corroboration / Content Match
        # Check if the evidence actually corroborates the claim statement
        # Tokenize key terms from claim (excluding stop words)
        stop_words = {"the", "a", "an", "is", "was", "are", "were", "this", "that", "in", "on", "at", "by", "for", "with", "about", "to", "of", "and", "or"}
        claim_words = [w.lower() for w in re.findall(r"[A-Za-z0-9_\-]+", claim_text) if w.lower() not in stop_words]

        # Combine all raw outputs of valid evidence
        combined_evidence_text = " ".join([ev.raw_output.lower() for ev in valid_evidence])

        # Check keyword overlap
        matched_words = [w for w in claim_words if w in combined_evidence_text]
        support_ratio = len(matched_words) / max(len(claim_words), 1)

        # Specifically recognize standard security claims:
        # e.g., "PowerShell execution occurred" matched against powershell evidence
        is_powershell_claim = "powershell" in claim_text.lower() and "powershell" in combined_evidence_text
        is_process_claim = ("process" in claim_text.lower() or "execution" in claim_text.lower()) and ("process" in combined_evidence_text or "powershell" in combined_evidence_text)

        if is_powershell_claim or is_process_claim or support_ratio >= 0.3:
            reason = f"Claim is directly corroborated by verified evidence ({', '.join(valid_ids)})."
            evaluations.append(
                ClaimEvaluation(
                    claim=claim_text,
                    status=ClaimStatus.SUPPORTED.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    valid_evidence_ids=valid_ids,
                    invalid_evidence_ids=[],
                )
            )
        else:
            reason = f"Referenced evidence ({', '.join(valid_ids)}) does not contain sufficient telemetry to corroborate claim: '{claim_text}'."
            evaluations.append(
                ClaimEvaluation(
                    claim=claim_text,
                    status=ClaimStatus.UNSUPPORTED.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    valid_evidence_ids=valid_ids,
                    invalid_evidence_ids=[],
                )
            )
            objections.append(
                CriticObjection(
                    claim=claim_text,
                    status=ClaimStatus.UNSUPPORTED.value,
                    reason=reason,
                    evidence_ids=ref_ids,
                    category="INSUFFICIENT_CORROBORATION",
                )
            )
            missing_evidence_list.append(f"Specific telemetry corroborating '{claim_text}'")

    # 4. Evaluate Draft Conclusion for Overconfidence and Overclaiming
    draft_tokens = _extract_overconfident_tokens(request.draft_conclusion)
    if draft_tokens:
        overclaim_msg = f"Draft conclusion uses overconfident language ({', '.join(draft_tokens)}) that exceeds evidentiary proof."
        if overclaim_msg not in overclaims_list:
            overclaims_list.append(overclaim_msg)
        objections.append(
            CriticObjection(
                claim=request.draft_conclusion,
                status=ClaimStatus.UNSUPPORTED.value,
                reason=f"Overconfident language ('{', '.join(draft_tokens)}') detected. The available evidence supports suspicious activity but does not establish absolute certainty.",
                evidence_ids=[],
                category="OVERCONFIDENT_LANGUAGE",
            )
        )

    # Check if draft conclusion claims attribution while no evidence in the entire investigation establishes attribution
    if _has_threat_actor_attribution(request.draft_conclusion):
        global_attribution_found = any(
            _has_threat_actor_attribution(ev.raw_output) for ev in investigation_evidence
        )
        if not global_attribution_found:
            msg = "Draft conclusion asserts threat-actor attribution, but no evidence in the investigation establishes this attribution."
            if msg not in overclaims_list:
                overclaims_list.append(msg)
            if "Evidence linking the observed activity to the specified threat actor" not in missing_evidence_list:
                missing_evidence_list.append("Evidence linking the observed activity to the specified threat actor")
            # Ensure an attribution objection exists for draft conclusion if not already present
            if not any(obj.category == "UNSUPPORTED_ATTRIBUTION" and obj.claim == request.draft_conclusion for obj in objections):
                objections.append(
                    CriticObjection(
                        claim=request.draft_conclusion,
                        status=ClaimStatus.UNSUPPORTED.value,
                        reason="No evidence ID establishes attribution to the threat actor referenced in the conclusion.",
                        evidence_ids=[],
                        category="UNSUPPORTED_ATTRIBUTION",
                    )
                )

    # 5. Determine Overall Status
    # Requires revision if ANY claim is unsupported/contradicted/invalid, or if objections/overclaims exist
    has_unsupported_claim = any(
        e.status in [
            ClaimStatus.UNSUPPORTED.value,
            ClaimStatus.CONTRADICTED.value,
            ClaimStatus.UNCERTAIN.value,
            ClaimStatus.INVALID_EVIDENCE_REFERENCE.value,
        ]
        for e in evaluations
    )
    requires_revision = has_unsupported_claim or len(objections) > 0 or len(overclaims_list) > 0

    overall_status = OverallCriticStatus.REQUIRES_REVISION.value if requires_revision else OverallCriticStatus.PASS.value

    # 6. Persist Critic Review in Database
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    review_id = generate_next_critic_id(db)

    review_model = CriticReviewModel(
        id=review_id,
        investigation_id=investigation_id,
        draft_conclusion=request.draft_conclusion,
        overall_status=overall_status,
        claims_evaluation=json.dumps([e.model_dump() for e in evaluations]),
        objections=json.dumps([o.model_dump() for o in objections]),
        missing_evidence=json.dumps(missing_evidence_list),
        contradictions=json.dumps(contradictions_list),
        overclaims=json.dumps(overclaims_list),
        created_at=now_utc,
    )

    db.add(review_model)
    db.commit()
    db.refresh(review_model)

    # Module 3K: Broadcast CRITIC_REVIEWED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{investigation_id}",
            event_type="CRITIC_REVIEWED",
            data={
                "review_id": review_model.id,
                "investigation_id": investigation_id,
                "overall_status": overall_status,
                "objections_count": len(objections),
                "contradictions_count": len(contradictions_list),
                "created_at": now_utc,
            },
            investigation_id=investigation_id,
        )
    except Exception:
        pass

    return CriticResponse(
        id=review_model.id,
        investigation_id=investigation_id,
        overall_status=overall_status,
        draft_conclusion=request.draft_conclusion,
        claims_evaluation=evaluations,
        objections=objections,
        missing_evidence=missing_evidence_list,
        contradictions=contradictions_list,
        overclaims=overclaims_list,
        created_at=now_utc,
    )


def get_latest_critic_review(db: Session, investigation_id: str) -> Optional[CriticResponse]:
    """Retrieve the most recent Critic review for an investigation."""
    review_model = (
        db.query(CriticReviewModel)
        .filter(CriticReviewModel.investigation_id == investigation_id)
        .order_by(CriticReviewModel.created_at.desc())
        .first()
    )
    if not review_model:
        return None

    claims_eval_data = review_model.get_claims_evaluation()
    objections_data = review_model.get_objections()

    evaluations = [ClaimEvaluation(**item) for item in claims_eval_data]
    objections = [CriticObjection(**item) for item in objections_data]

    return CriticResponse(
        id=review_model.id,
        investigation_id=review_model.investigation_id,
        overall_status=review_model.overall_status,
        draft_conclusion=review_model.draft_conclusion,
        claims_evaluation=evaluations,
        objections=objections,
        missing_evidence=review_model.get_missing_evidence(),
        contradictions=review_model.get_contradictions(),
        overclaims=review_model.get_overclaims(),
        created_at=review_model.created_at,
    )
