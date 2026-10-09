"""
Trust Score Service (Module 3G)
Agentic SOC — Auditable AI Security Operations Center

Deterministic calculation of Evidence & Audit Quality Trust Score (0-100).
Measures evidentiary backing, cryptographic SHA-256 integrity, claim corroboration,
and multi-agent audit completeness.

This score measures evidence/audit quality, NOT likelihood or probability of attack.
Formula is 100% deterministic, transparent, and explainable with zero hidden factors.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.schemas.canonical_case import CanonicalCaseJson
from app.schemas.trust_score import (
    ScoreComponent,
    Penalty,
    ScoreExplanation,
    TrustScore,
    VerdictType,
)
from app.services.auditor_service import export_canonical_case

FORMULA_SPECIFICATION = (
    "Trust Score = clamp(0.0, 100.0, round("
    "Evidence Coverage [25.0] + Evidence Integrity [25.0] + Claim Support [30.0] + Audit Completeness [20.0] "
    "- (Contradiction Penalties + Unsupported Claim Penalties + Uncertainty Penalties + Failed Integrity Penalties), 1))"
)


def compute_trust_score(case: CanonicalCaseJson) -> TrustScore:
    """
    Compute deterministic Evidence & Audit Quality Trust Score (0-100) from a Canonical Case JSON.
    Guarantees:
    - Same input produces the exact same score.
    - Result strictly bounded between 0.0 and 100.0.
    - All component contributions reconcile with the final score.
    - Does NOT execute tools or mutate evidence.
    """
    # 1. Extract case metrics
    claims = case.claims or []
    total_claims = len(claims)

    # Evidence items list extraction
    if isinstance(case.evidence, dict):
        ev_items = list(case.evidence.values())
    elif isinstance(case.evidence, list):
        ev_items = case.evidence
    else:
        ev_items = []
    total_evidence = len(ev_items)

    audit = case.audit
    contradictions = case.contradictions or []
    uncertainties = case.uncertainties or []
    unsupported_claims = case.unsupported_claims or []

    # 2. Base Components (Maximum 100.0 points total)

    # Component 1: Evidence Coverage (Weight: 25.0)
    claims_with_evidence = sum(1 for c in claims if len(c.evidence_ids) > 0)
    cov_ratio = (claims_with_evidence / total_claims) if total_claims > 0 else 0.0
    cov_contribution = round(25.0 * cov_ratio, 1)
    cov_explanation = (
        f"{claims_with_evidence} of {total_claims} claims reference verified evidence items ({int(cov_ratio * 100)}%)."
        if total_claims > 0
        else "No claims present in case file (0.0 pts)."
    )
    comp_coverage = ScoreComponent(
        name="Evidence Coverage",
        value=round(cov_ratio, 3),
        weight=25.0,
        contribution=cov_contribution,
        explanation=cov_explanation,
    )

    # Component 2: Evidence Integrity (Weight: 25.0)
    valid_integrity_items = sum(
        1 for ev in ev_items if getattr(ev, "integrity_status", "") == "VALID"
    )
    failed_integrity_items = sum(
        1 for ev in ev_items if getattr(ev, "integrity_status", "") == "FAILED"
    )
    integ_ratio = (valid_integrity_items / total_evidence) if total_evidence > 0 else 0.0
    integ_contribution = round(25.0 * integ_ratio, 1)
    integ_explanation = (
        f"{valid_integrity_items} of {total_evidence} referenced evidence items passed SHA-256 cryptographic verification ({int(integ_ratio * 100)}%)."
        if total_evidence > 0
        else "No evidence objects in ledger to verify (0.0 pts)."
    )
    comp_integrity = ScoreComponent(
        name="Evidence Integrity",
        value=round(integ_ratio, 3),
        weight=25.0,
        contribution=integ_contribution,
        explanation=integ_explanation,
    )

    # Component 3: Claim Support (Weight: 30.0)
    supported_claims_count = sum(1 for c in claims if c.status == "SUPPORTED")
    support_ratio = (supported_claims_count / total_claims) if total_claims > 0 else 0.0
    support_contribution = round(30.0 * support_ratio, 1)
    support_explanation = (
        f"{supported_claims_count} of {total_claims} evaluated claims are fully supported by telemetry ({int(support_ratio * 100)}%)."
        if total_claims > 0
        else "No claims evaluated (0.0 pts)."
    )
    comp_support = ScoreComponent(
        name="Claim Support",
        value=round(support_ratio, 3),
        weight=30.0,
        contribution=support_contribution,
        explanation=support_explanation,
    )

    # Component 4: Audit Completeness (Weight: 20.0)
    auditor_pts = 12.0 if (audit and audit.auditor_verified and audit.audit_status == "AUDIT_VERIFIED") else 0.0
    critic_pts = 8.0 if (audit and audit.critic_reviewed) else 0.0
    audit_contribution = round(auditor_pts + critic_pts, 1)
    audit_ratio = audit_contribution / 20.0

    if auditor_pts > 0 and critic_pts > 0:
        audit_explanation = "Full multi-agent review completed: Auditor verified (12.0 pts) and Critic reviewed (8.0 pts)."
    elif auditor_pts > 0:
        audit_explanation = "Auditor verified (12.0 pts); Critic red-team review not performed (0.0 pts)."
    elif critic_pts > 0:
        audit_explanation = "Critic reviewed (8.0 pts); Auditor verification pending (0.0 pts)."
    else:
        audit_explanation = "Investigation has not completed Auditor verification or Critic review (0.0 pts)."

    comp_audit = ScoreComponent(
        name="Audit Completeness",
        value=round(audit_ratio, 3),
        weight=20.0,
        contribution=audit_contribution,
        explanation=audit_explanation,
    )

    score_components = [comp_coverage, comp_integrity, comp_support, comp_audit]

    # 3. Penalties (Deterministic Subtractions)
    penalties: List[Penalty] = []

    # Penalty 1: Contradictions (Rate: 15.0 per conflict, Max: 30.0)
    contradiction_count = len(contradictions)
    if contradiction_count > 0:
        rate = 15.0
        deduction = round(min(float(contradiction_count) * rate, 30.0), 1)
        penalties.append(
            Penalty(
                name="Contradiction Penalty",
                value=contradiction_count,
                rate_per_unit=rate,
                deduction=deduction,
                explanation=f"{contradiction_count} contradictory evidence conflict(s) detected (-{deduction} pts).",
            )
        )

    # Penalty 2: Unsupported Claims (Rate: 10.0 per claim, Max: 30.0)
    unsupported_count = len(unsupported_claims)
    if unsupported_count > 0:
        rate = 10.0
        deduction = round(min(float(unsupported_count) * rate, 30.0), 1)
        penalties.append(
            Penalty(
                name="Unsupported Claim Penalty",
                value=unsupported_count,
                rate_per_unit=rate,
                deduction=deduction,
                explanation=f"{unsupported_count} unsupported claim(s) asserted without evidence (-{deduction} pts).",
            )
        )

    # Penalty 3: Uncertainties (Rate: 5.0 per uncertainty, Max: 15.0)
    uncertainty_count = len(uncertainties)
    if uncertainty_count > 0:
        rate = 5.0
        deduction = round(min(float(uncertainty_count) * rate, 15.0), 1)
        penalties.append(
            Penalty(
                name="Uncertainty Penalty",
                value=uncertainty_count,
                rate_per_unit=rate,
                deduction=deduction,
                explanation=f"{uncertainty_count} unresolved uncertainty item(s) logged (-{deduction} pts).",
            )
        )

    # Penalty 4: Cryptographic Failed Integrity (Rate: 15.0 per failed item, Max: 30.0)
    if failed_integrity_items > 0:
        rate = 15.0
        deduction = round(min(float(failed_integrity_items) * rate, 30.0), 1)
        penalties.append(
            Penalty(
                name="Failed Integrity Penalty",
                value=failed_integrity_items,
                rate_per_unit=rate,
                deduction=deduction,
                explanation=f"{failed_integrity_items} evidence item(s) failed SHA-256 hash verification (-{deduction} pts).",
            )
        )

    # 4. Final Reconciled Score Calculation
    base_sum = sum(c.contribution for c in score_components)
    total_deductions = sum(p.deduction for p in penalties)
    raw_score = base_sum - total_deductions
    final_score = round(max(0.0, min(100.0, raw_score)), 1)

    # 5. Quality Verdict and Narrative Findings
    if final_score >= 85.0:
        verdict: VerdictType = "HIGH_TRUST"
    elif final_score >= 65.0:
        verdict = "MODERATE_TRUST"
    elif final_score >= 40.0:
        verdict = "LOW_TRUST"
    else:
        verdict = "UNTRUSTED"

    key_findings: List[str] = []
    if integ_ratio == 1.0 and total_evidence > 0:
        key_findings.append(f"All {total_evidence} evidence item(s) verified tamper-evident via SHA-256 hashes.")
    elif failed_integrity_items > 0:
        key_findings.append(f"CRITICAL: {failed_integrity_items} evidence item(s) failed cryptographic verification.")

    if supported_claims_count == total_claims and total_claims > 0:
        key_findings.append("100% of claims are fully corroborated by telemetry.")
    elif unsupported_count > 0:
        key_findings.append(f"{unsupported_count} claim(s) lacked supporting evidence (NO EVIDENCE -> NO CLAIM).")

    if contradiction_count > 0:
        key_findings.append(f"Conflicting telemetry detected across {contradiction_count} evidence source(s).")

    if audit and audit.auditor_verified:
        key_findings.append("Auditor Agent verification verified and sealed.")

    summary = (
        f"Evidence & Audit Quality Score: {final_score}/100 ({verdict}). "
        f"Measures evidence backing ({comp_coverage.contribution}/{comp_coverage.weight} pts), "
        f"cryptographic integrity ({comp_integrity.contribution}/{comp_integrity.weight} pts), "
        f"claim support ({comp_support.contribution}/{comp_support.weight} pts), and "
        f"audit completeness ({comp_audit.contribution}/{comp_audit.weight} pts), "
        f"with {len(penalties)} penalty deduction(s) totaling -{total_deductions} pts. "
        f"Does NOT represent probability of attack."
    )

    explanation = ScoreExplanation(
        summary=summary,
        formula=FORMULA_SPECIFICATION,
        verdict=verdict,
        key_findings=key_findings,
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return TrustScore(
        case_id=case.case_id,
        investigation_id=case.investigation_id,
        trust_score=final_score,
        score_components=score_components,
        penalties=penalties,
        explanation=explanation,
        calculated_at=now_utc,
    )


def get_investigation_trust_score(
    db: Session,
    investigation_id: str,
    case_id: Optional[str] = None,
) -> TrustScore:
    """
    Retrieve or compute the Trust Score for an investigation from its canonical Case JSON.
    Also syncs the computed integer score with the parent investigation record.
    """
    # 1. Export or load the Canonical Case JSON for this investigation
    case_json = export_canonical_case(db, investigation_id, case_id)

    # 2. Compute the deterministic Trust Score
    score = compute_trust_score(case_json)

    # 3. Sync trust score with the InvestigationModel in SQLite
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if inv:
        inv.trust_score = int(round(score.trust_score))
        db.commit()

    # Module 3K: Broadcast TRUST_SCORE_UPDATED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{investigation_id}",
            event_type="TRUST_SCORE_UPDATED",
            data={
                "case_id": score.case_id,
                "investigation_id": investigation_id,
                "trust_score": score.trust_score,
                "verdict": score.explanation.verdict,
                "calculated_at": score.calculated_at,
            },
            investigation_id=investigation_id,
        )
    except Exception:
        pass

    return score
