from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class CriticAdversarialFinding(BaseModel):
    """Granular adversarial finding produced by the Critic / Red-Team Agent."""
    finding_id: str = Field(..., description="Unique finding ID (e.g. FIND-001)")
    category: str = Field(..., description="Category: EXECUTION_VERIFICATION, PERSISTENCE_CHECK, REPUTATION_ANALYSIS, BENIGN_CONTEXT, CONTRADICTION, ATTRIBUTION_GUARD")
    finding_text: str = Field(..., description="Adversarial finding summary statement")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="Evidence IDs bound to this finding")
    contradicts_preliminary: bool = Field(False, description="Whether this finding contradicts the preliminary conclusion")
    status: str = Field(..., description="Finding status: CONFIRMED, INCONCLUSIVE, UNSUPPORTED, AUTHORIZED_ACTIVITY")
    counter_argument: str = Field(..., description="Detailed adversarial counter-argument challenging investigator assumptions")


class ContradictionAnalysis(BaseModel):
    """Explicit contradiction detected between conflicting evidence items or hypotheses."""
    contradiction_id: str = Field(..., description="Unique contradiction ID (e.g. CTRD-001)")
    evidence_a_id: str = Field(..., description="First conflicting evidence ID")
    evidence_a_summary: str = Field(..., description="Summary of evidence A assertion")
    evidence_b_id: str = Field(..., description="Second conflicting evidence ID")
    evidence_b_summary: str = Field(..., description="Summary of evidence B assertion")
    conflict_type: str = Field(..., description="Category of conflict, e.g. MALICIOUS_EXECUTION_VS_AUTHORIZED_TESTING")
    impact_assessment: str = Field(..., description="Analytical impact on preliminary investigator conclusion")
    resolution: str = Field(..., description="Critic agent resolution of the contradiction")


class AttributionGuardEvaluation(BaseModel):
    """Enforcement of the Threat Actor Attribution Policy Rule."""
    policy_name: str = Field("Threat Actor Attribution Policy", description="Governing policy name")
    policy_rule: str = Field(
        "The system cannot assert a specific threat actor unless sufficient evidence supports the attribution.",
        description="Formal governing attribution policy rule"
    )
    asserted_threat_actor: Optional[str] = Field(None, description="Asserted threat actor name (e.g. APT-29)")
    attribution_status: str = Field("NOT ESTABLISHED", description="Attribution status: NOT ESTABLISHED, ESTABLISHED, WITHHELD")
    evidence_sufficiency: str = Field("INSUFFICIENT", description="Evidence sufficiency status: INSUFFICIENT, SUFFICIENT")
    action: str = Field("ATTRIBUTION_BLOCKED", description="Action taken: ATTRIBUTION_BLOCKED, ATTRIBUTION_PERMITTED")
    reason: str = Field(
        "No evidence IDs sufficiently support threat-actor attribution.",
        description="Detailed justification for policy enforcement"
    )


class RedTeamChallengeRequest(BaseModel):
    """Request payload to trigger Critic / Red-Team adversarial challenge against a conclusion."""
    investigation_id: Optional[str] = Field("INV-001", description="Associated investigation ID")
    scenario_id: Optional[str] = Field("SCN-PEN-TEST", description="Adversarial scenario template ID")
    preliminary_conclusion: str = Field(
        "Endpoint compromised by malware.",
        description="Preliminary investigator or analyst conclusion under attack"
    )
    attacker_hypothesis: Optional[str] = Field(
        "External adversary executed PowerShell payload and established persistence",
        description="Preliminary attacker hypothesis being tested"
    )
    asserted_threat_actor: Optional[str] = Field(
        "APT-29 (Cozy Bear)",
        description="Threat actor asserted in preliminary report (if any)"
    )
    evidence_ids: Optional[List[str]] = Field(
        default_factory=lambda: ["EV-001", "EV-002", "EV-003", "EV-004"],
        description="List of evidence IDs to evaluate"
    )


class RedTeamChallengeResponse(BaseModel):
    """Adversarial evaluation report produced by the Critic / Red-Team Agent."""
    challenge_id: str = Field(..., description="Unique challenge report ID (e.g. RTC-2026-001)")
    investigation_id: str = Field(..., description="Evaluated investigation ID")
    preliminary_conclusion: str = Field(..., description="Preliminary conclusion that was challenged")
    attacker_hypothesis: str = Field(..., description="Attacker hypothesis evaluated")
    critic_findings: List[CriticAdversarialFinding] = Field(..., description="List of 4+ adversarial critic findings")
    contradictions: List[ContradictionAnalysis] = Field(..., description="List of detected evidence contradictions")
    attribution_guard: AttributionGuardEvaluation = Field(..., description="Threat Actor Attribution Policy status")
    final_critic_decision: str = Field(
        "Insufficient evidence for confirmed compromise.",
        description="Final deterministic verdict of the Critic / Red-Team Agent"
    )
    verdict_category: str = Field(
        "AUTHORIZED_TESTING",
        description="Verdict category: AUTHORIZED_TESTING, REFUTED, CHALLENGED, UPHELD"
    )
    original_trust_score: float = Field(..., description="Original trust score before challenge (0-100)")
    revised_trust_score: float = Field(..., description="Revised trust score after adversarial deductions (0-100)")
    tamper_proof_signature: str = Field(..., description="SHA-256 cryptographic signature of this adversarial report")
    timestamp: str = Field(..., description="ISO 8601 evaluation timestamp")


class RedTeamScenarioPreset(BaseModel):
    """Pre-packaged adversarial challenge scenario."""
    scenario_id: str = Field(..., description="Scenario ID (e.g. SCN-PEN-TEST)")
    title: str = Field(..., description="Scenario title")
    description: str = Field(..., description="Detailed description of the adversarial scenario")
    preliminary_conclusion: str = Field(..., description="Initial draft conclusion")
    attacker_hypothesis: str = Field(..., description="Investigator attacker hypothesis")
    asserted_threat_actor: Optional[str] = Field(None, description="Asserted threat actor")
    expected_verdict: str = Field(..., description="Expected final Critic decision")


class InteractiveDemoStep(BaseModel):
    """Single step result within the 7-stage Interactive Demo simulation pipeline."""
    step_id: str = Field(..., description="Step key: start_investigation, run_planner, collect_evidence, run_analysis, challenge_conclusion, audit_case, replay_investigation")
    step_name: str = Field(..., description="Human-readable step name")
    step_number: int = Field(..., description="Sequential step number (1 to 7)")
    agent_id: str = Field(..., description="Executing agent ID (e.g. agent-planner, agent-critic)")
    agent_name: str = Field(..., description="Executing agent display name")
    status: str = Field("completed", description="Execution status: completed, active, pending")
    action_summary: str = Field(..., description="Summary of action performed during this step")
    telemetry_logs: List[str] = Field(default_factory=list, description="Telemetry logs generated by this step")
    evidence_ids: List[str] = Field(default_factory=list, description="Evidence items referenced or created")
    trust_score: float = Field(..., description="Current trust score at this step")
    claims_count: int = Field(..., description="Number of claims verified or active")
    current_conclusion: str = Field(..., description="Current investigative conclusion at this point")
    timestamp: str = Field(..., description="ISO 8601 execution timestamp")


class InteractiveDemoSessionState(BaseModel):
    """Complete state of the 7-stage Interactive Demo simulation pipeline."""
    session_id: str = Field(..., description="Session identifier")
    case_id: str = Field("CASE-2026-0042", description="Active case ID under investigation")
    current_step_id: str = Field(..., description="Active step ID")
    current_step_number: int = Field(..., description="Active step number (1 to 7)")
    is_complete: bool = Field(False, description="Whether all 7 steps have been executed")
    completed_steps: List[InteractiveDemoStep] = Field(default_factory=list, description="Historical execution steps")
    available_steps: List[str] = Field(default_factory=list, description="All 7 steps in sequential order")
    cumulative_evidence: List[str] = Field(default_factory=list, description="All evidence collected so far")
    latest_telemetry: List[str] = Field(default_factory=list, description="Recent telemetry stream lines")
    current_trust_score: float = Field(..., description="Current overall trust score")
    current_verdict: str = Field(..., description="Current platform verdict")
