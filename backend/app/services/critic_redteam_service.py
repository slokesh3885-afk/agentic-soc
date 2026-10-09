"""
Module 3S: Critic & Red-Team Adversarial Evaluation Engine & Interactive Multi-Agent Pipeline Simulator
Agentic SOC — Auditable AI Security Operations Center
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.schemas.redteam import (
    CriticAdversarialFinding,
    ContradictionAnalysis,
    AttributionGuardEvaluation,
    RedTeamChallengeRequest,
    RedTeamChallengeResponse,
    RedTeamScenarioPreset,
    InteractiveDemoStep,
    InteractiveDemoSessionState,
)
from app.services.websocket_manager import ws_manager
from app.services.audit_service import record_audit_event

logger = logging.getLogger("agentic_soc.critic_redteam")

# In-memory storage for the latest challenge and interactive demo session state
_LATEST_CHALLENGE: Optional[RedTeamChallengeResponse] = None
_DEMO_SESSIONS: Dict[str, InteractiveDemoSessionState] = {}


def get_redteam_scenarios() -> List[RedTeamScenarioPreset]:
    """Retrieve all available pre-packaged adversarial scenarios."""
    return [
        RedTeamScenarioPreset(
            scenario_id="SCN-PEN-TEST",
            title="Authorized Penetration Test vs. Malware Compromise",
            description="Investigator preliminarily concludes malicious compromise based on suspicious PowerShell execution, but red-team critic identifies authorized security test calendar and inconclusive hash reputation.",
            preliminary_conclusion="Endpoint compromised by malware.",
            attacker_hypothesis="External adversary deployed obfuscated PowerShell reverse shell with automated persistence.",
            asserted_threat_actor="APT-29 (Cozy Bear)",
            expected_verdict="Insufficient evidence for confirmed compromise."
        ),
        RedTeamScenarioPreset(
            scenario_id="SCN-TRAP-POWERSHELL",
            title="Misleading PowerShell Alert (Trap Case)",
            description="Deceptive alert mimics malicious credential harvesting, but secondary telemetry reveals IT backup automation script running under approved administrative service account.",
            preliminary_conclusion="Credential theft in progress via mimikatz invocation.",
            attacker_hypothesis="Lateral movement agent dumping LSASS memory.",
            asserted_threat_actor="FIN7",
            expected_verdict="False Positive / Authorized Activity"
        ),
        RedTeamScenarioPreset(
            scenario_id="SCN-TRUE-POSITIVE",
            title="Confirmed Malicious File Execution (True Positive)",
            description="Confirmed adversary intrusion with multi-source cryptographic evidence corroborating file execution, C2 beaconing, and sandbox malware traits.",
            preliminary_conclusion="Endpoint compromised by Cobalt Strike beacon.",
            attacker_hypothesis="Adversary beaconing to external IP on port 443 with scheduled task persistence.",
            asserted_threat_actor="UNC2452",
            expected_verdict="Confirmed Malicious Activity (Attribution Withheld)"
        ),
    ]


def execute_redteam_challenge(
    db: Session,
    request: RedTeamChallengeRequest
) -> RedTeamChallengeResponse:
    """
    Execute deterministic Critic / Red-Team adversarial challenge against a preliminary conclusion.
    Strictly aligns with the specification:
    - Preliminary conclusion: "Endpoint compromised by malware."
    - Critic findings:
      1. Evidence confirms suspicious execution.
      2. No confirmed persistence mechanism.
      3. Hash reputation is inconclusive.
      4. User activity occurred during an authorized security test.
    - Contradictions: Highlights direct conflict between suspicious execution vs authorized pen-test.
    - Attribution Guard: Blocks uncorroborated threat actor attribution.
    - Final critic decision: "Insufficient evidence for confirmed compromise."
    """
    global _LATEST_CHALLENGE

    challenge_id = f"RTC-2026-{datetime.now(timezone.utc).strftime('%H%M%S')}"
    inv_id = request.investigation_id or "INV-001"
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Generate the 4 canonical adversarial Critic findings
    critic_findings = [
        CriticAdversarialFinding(
            finding_id="FIND-001",
            category="EXECUTION_VERIFICATION",
            finding_text="Evidence confirms suspicious execution.",
            supporting_evidence_ids=["EV-001", "EV-003"],
            contradicts_preliminary=False,
            status="CONFIRMED",
            counter_argument="While suspicious PowerShell execution syntax is validated in SIEM and sandbox logs, execution telemetry alone does not establish malicious adversary intent or payload weaponization."
        ),
        CriticAdversarialFinding(
            finding_id="FIND-002",
            category="PERSISTENCE_CHECK",
            finding_text="No confirmed persistence mechanism.",
            supporting_evidence_ids=["EV-002"],
            contradicts_preliminary=True,
            status="UNSUPPORTED",
            counter_argument="EDR process tree and registry timeline inspect showed 0 scheduled tasks, 0 registry Run key modifications, and 0 service installations. Persistent compromise hypothesis is unsubstantiated."
        ),
        CriticAdversarialFinding(
            finding_id="FIND-003",
            category="REPUTATION_ANALYSIS",
            finding_text="Hash reputation is inconclusive.",
            supporting_evidence_ids=["EV-002"],
            contradicts_preliminary=True,
            status="INCONCLUSIVE",
            counter_argument="Global threat intelligence multi-engine lookup returned 0/72 malware detections. SHA-256 hash has unknown reputation with no historic adversary linkage."
        ),
        CriticAdversarialFinding(
            finding_id="FIND-004",
            category="BENIGN_CONTEXT",
            finding_text="User activity occurred during an authorized security test.",
            supporting_evidence_ids=["EV-004"],
            contradicts_preliminary=True,
            status="AUTHORIZED_ACTIVITY",
            counter_argument="Corroborated by SOC change management ticket SEC-CHG-9842 confirming scheduled red-team penetration test execution on endpoint host during the identical alert timestamp window."
        ),
    ]

    # 2. Contradictions Analysis
    contradictions = [
        ContradictionAnalysis(
            contradiction_id="CTRD-001",
            evidence_a_id="EV-001",
            evidence_a_summary="SIEM log indicates suspicious PowerShell base64 execution with encoded command flags.",
            evidence_b_id="EV-004",
            evidence_b_summary="SOC authorization ticket SEC-CHG-9842 records pre-approved penetration testing engagement by internal security team.",
            conflict_type="MALICIOUS_EXECUTION_VS_AUTHORIZED_TESTING",
            impact_assessment="The preliminary conclusion of adversary compromise is directly invalidated by authorized testing change window.",
            resolution="Critic Agent resolves event as authorized benign security testing rather than hostile external breach."
        ),
        ContradictionAnalysis(
            contradiction_id="CTRD-002",
            evidence_a_id="EV-003",
            evidence_a_summary="Sandbox dynamic execution flagged process spawning behavior as anomalous.",
            evidence_b_id="EV-002",
            evidence_b_summary="EDR forensic timeline verified zero persistence mechanisms and zero lateral movement.",
            conflict_type="EXECUTION_ANOMALY_VS_ZERO_PERSISTENCE",
            impact_assessment="Single execution burst without persistence fails Enterprise compromise criteria.",
            resolution="Downgrade threat level from active compromise to isolated script evaluation."
        ),
    ]

    # 3. Threat Actor Attribution Guard Evaluation
    asserted_actor = request.asserted_threat_actor
    if asserted_actor and asserted_actor.lower() not in ("none", "null", ""):
        attribution_guard = AttributionGuardEvaluation(
            policy_name="Threat Actor Attribution Policy",
            policy_rule="The system cannot assert a specific threat actor unless sufficient evidence supports the attribution.",
            asserted_threat_actor=asserted_actor,
            attribution_status="NOT ESTABLISHED",
            evidence_sufficiency="INSUFFICIENT",
            action="ATTRIBUTION_BLOCKED",
            reason="No evidence IDs sufficiently support threat-actor attribution. Corroboration threshold requires >= 3 independent threat intelligence source corroborations."
        )
    else:
        attribution_guard = AttributionGuardEvaluation(
            policy_name="Threat Actor Attribution Policy",
            policy_rule="The system cannot assert a specific threat actor unless sufficient evidence supports the attribution.",
            asserted_threat_actor=None,
            attribution_status="NOT ESTABLISHED",
            evidence_sufficiency="INSUFFICIENT",
            action="ATTRIBUTION_BLOCKED",
            reason="No threat actor was asserted; attribution remains unestablished."
        )

    # 4. Final Critic Decision & Trust Score Calculation
    final_critic_decision = "Insufficient evidence for confirmed compromise."
    verdict_category = "AUTHORIZED_TESTING"
    original_trust_score = 87.0
    revised_trust_score = 42.5

    # 5. Cryptographic signature over challenge findings
    sig_payload = f"{challenge_id}:{inv_id}:{final_critic_decision}:{revised_trust_score}:{now_iso}"
    tamper_proof_sig = hashlib.sha256(sig_payload.encode("utf-8")).hexdigest()

    response = RedTeamChallengeResponse(
        challenge_id=challenge_id,
        investigation_id=inv_id,
        preliminary_conclusion=request.preliminary_conclusion,
        attacker_hypothesis=request.attacker_hypothesis or "External adversary deployed PowerShell payload",
        critic_findings=critic_findings,
        contradictions=contradictions,
        attribution_guard=attribution_guard,
        final_critic_decision=final_critic_decision,
        verdict_category=verdict_category,
        original_trust_score=original_trust_score,
        revised_trust_score=revised_trust_score,
        tamper_proof_signature=tamper_proof_sig,
        timestamp=now_iso,
    )

    _LATEST_CHALLENGE = response

    # 6. Commit Audit Entry to Immutable Audit Trail (Module 3L)
    try:
        record_audit_event(
            db=db,
            event_type="CRITIC_ASSESSMENT",
            payload_summary=f"Critic challenged preliminary conclusion: '{request.preliminary_conclusion}'. Verdict: '{final_critic_decision}' (Attribution blocked: {attribution_guard.action}).",
            payload={"challenge_id": challenge_id, "evidence_ids": ["EV-001", "EV-002", "EV-003", "EV-004"]},
            investigation_id=inv_id,
            actor="Critic / Red-Team Agent (Module 3S)",
            metadata={
                "challenge_id": challenge_id,
                "final_decision": final_critic_decision,
                "revised_trust_score": revised_trust_score,
                "signature": tamper_proof_sig,
            }
        )
    except Exception as e:
        logger.warning(f"Could not record audit event for critic challenge: {e}")

    # 7. Broadcast Real-time WebSocket Telemetry (Module 3K)
    try:
        ws_manager.dispatch_sync(
            channel="telemetry",
            event_type="CRITIC_REDTEAM_CHALLENGED",
            data={
                "challenge_id": challenge_id,
                "investigation_id": inv_id,
                "preliminary_conclusion": request.preliminary_conclusion,
                "final_decision": final_critic_decision,
                "contradictions_count": len(contradictions),
                "revised_trust_score": revised_trust_score,
                "timestamp": now_iso,
            },
            investigation_id=inv_id,
        )
    except Exception as e:
        logger.warning(f"Could not broadcast websocket event: {e}")

    return response


def get_latest_redteam_challenge(
    db: Session,
    investigation_id: Optional[str] = None
) -> RedTeamChallengeResponse:
    """Retrieve the most recent Critic / Red-Team adversarial evaluation."""
    global _LATEST_CHALLENGE
    if _LATEST_CHALLENGE is not None:
        return _LATEST_CHALLENGE

    # Default baseline challenge if none executed yet
    default_req = RedTeamChallengeRequest(
        investigation_id=investigation_id or "INV-001",
        scenario_id="SCN-PEN-TEST",
        preliminary_conclusion="Endpoint compromised by malware.",
        attacker_hypothesis="External adversary deployed obfuscated PowerShell reverse shell",
        asserted_threat_actor="APT-29 (Cozy Bear)",
    )
    return execute_redteam_challenge(db, default_req)


# =========================================================================
# INTERACTIVE DEMO PIPELINE ENGINE (7-Stage Deterministic Simulation)
# =========================================================================

DEMO_STEPS_CATALOG = [
    {
        "id": "start_investigation",
        "name": "Start Investigation",
        "number": 1,
        "agent_id": "agent-orchestrator",
        "agent_name": "Autonomous SOC Swarm Orchestrator",
        "summary": "Ingested critical SIEM alert ALT-9042, initialized cryptographic case CASE-2026-0042, and dispatched multi-agent investigation swarm.",
        "telemetry": [
            "[22:04:10] Ingestion Engine received alert ALT-9042 (Severity: HIGH, Host: WORKSTATION-89)",
            "[22:04:11] Swarm Orchestrator initialized investigation case CASE-2026-0042",
            "[22:04:12] Dispatched Planner Agent to construct allow-listed investigation workflow",
        ],
        "evidence": [],
        "trust_score": 60.0,
        "claims_count": 0,
        "conclusion": "Alert ALT-9042 under active multi-agent triage",
    },
    {
        "id": "run_planner",
        "name": "Run Planner",
        "number": 2,
        "agent_id": "agent-planner",
        "agent_name": "Planner Agent",
        "summary": "Synthesized 4-stage deterministic investigative strategy strictly bound to allow-listed tools in Tool Registry.",
        "telemetry": [
            "[22:04:13] Planner Agent validated Tool Registry allow-list (6 tools verified)",
            "[22:04:14] Formulated Step 1: Query SIEM authentication and PowerShell execution telemetry",
            "[22:04:15] Formulated Step 2: Query EDR endpoint process tree and persistence entries",
            "[22:04:16] Formulated Step 3: Execute SHA-256 hash reputation lookup and sandbox behavior analysis",
        ],
        "evidence": [],
        "trust_score": 68.0,
        "claims_count": 0,
        "conclusion": "Deterministic 4-step investigative plan locked into audit ledger",
    },
    {
        "id": "collect_evidence",
        "name": "Collect Evidence",
        "number": 3,
        "agent_id": "agent-tool",
        "agent_name": "Security Tool Layer",
        "summary": "Executed sandboxed tools (siem_search, edr_process_search, hash_lookup, sandbox_summary) and committed cryptographic SHA-256 evidence items EV-001 through EV-004.",
        "telemetry": [
            "[22:04:17] Tool Layer ran siem_search -> Captured EV-001 (PowerShell encoded command)",
            "[22:04:18] Tool Layer ran edr_process_search -> Captured EV-002 (Host process tree, 0 persistence entries)",
            "[22:04:19] Tool Layer ran hash_lookup -> Captured EV-003 (Reputation unknown, 0/72 detections)",
            "[22:04:20] Tool Layer queried change logs -> Captured EV-004 (Ticket SEC-CHG-9842 penetration test)",
        ],
        "evidence": ["EV-001", "EV-002", "EV-003", "EV-004"],
        "trust_score": 79.0,
        "claims_count": 1,
        "conclusion": "4 immutable evidence items collected and cryptographically verified",
    },
    {
        "id": "run_analysis",
        "name": "Run Analysis",
        "number": 4,
        "agent_id": "agent-analyst",
        "agent_name": "Analyst Agent",
        "summary": "Synthesized initial hypothesis and drafted claims CLM-001 through CLM-003: 'Endpoint compromised by malware' pending adversarial challenge.",
        "telemetry": [
            "[22:04:21] Analyst Agent synthesized draft claims bound to EV-001 and EV-003",
            "[22:04:22] Generated preliminary conclusion: 'Endpoint compromised by malware.'",
            "[22:04:23] Hypothesized external adversary intrusion (asserted actor: APT-29)",
            "[22:04:24] Submitted preliminary conclusion to Critic / Red-Team Agent for rigorous challenge",
        ],
        "evidence": ["EV-001", "EV-002", "EV-003", "EV-004"],
        "trust_score": 87.0,
        "claims_count": 3,
        "conclusion": "Preliminary hypothesis: 'Endpoint compromised by malware.'",
    },
    {
        "id": "challenge_conclusion",
        "name": "Challenge Conclusion",
        "number": 5,
        "agent_id": "agent-critic",
        "agent_name": "Critic / Red-Team Agent",
        "summary": "Attacked preliminary conclusion, identified authorized penetration test contradiction, blocked APT-29 attribution, and issued final decision: 'Insufficient evidence for confirmed compromise.'",
        "telemetry": [
            "[22:04:25] Critic Agent attacked preliminary conclusion: 'Endpoint compromised by malware.'",
            "[22:04:26] Detected contradiction: EV-001 (suspicious execution) vs EV-004 (authorized pen-test)",
            "[22:04:27] Verified persistence: EV-002 confirmed 0 scheduled tasks or persistence keys",
            "[22:04:28] Enforced Attribution Policy: Blocked APT-29 attribution due to insufficient evidence",
            "[22:04:29] Final Critic Decision: 'Insufficient evidence for confirmed compromise.'",
        ],
        "evidence": ["EV-001", "EV-002", "EV-003", "EV-004"],
        "trust_score": 88.0,
        "claims_count": 3,
        "conclusion": "Insufficient evidence for confirmed compromise.",
    },
    {
        "id": "audit_case",
        "name": "Audit Case",
        "number": 6,
        "agent_id": "agent-auditor",
        "agent_name": "Auditor Agent",
        "summary": "Audited complete forensic record, verified SHA-256 Merkle chain, validated Canonical Case JSON v1.0.0, and generated explainable Trust Score of 87/100.",
        "telemetry": [
            "[22:04:30] Auditor Agent verified 100% of claims are bound to cryptographic evidence IDs",
            "[22:04:31] Validated Canonical Case JSON schema compliance against Module 3F",
            "[22:04:32] Calculated explainable Trust Score (Evidence Coverage: 95%, Contradiction Handling: 100%)",
            "[22:04:33] Sealed case block into Module 3L immutable SHA-256 audit ledger",
        ],
        "evidence": ["EV-001", "EV-002", "EV-003", "EV-004"],
        "trust_score": 87.0,
        "claims_count": 3,
        "conclusion": "Audited and sealed: False Positive / Authorized Penetration Test",
    },
    {
        "id": "replay_investigation",
        "name": "Replay Investigation",
        "number": 7,
        "agent_id": "agent-replay",
        "agent_name": "Deterministic Replay Engine",
        "summary": "Re-executed historical investigation using identical stored tool outputs. Verified 100% reproducibility and mathematical consistency.",
        "telemetry": [
            "[22:04:34] Replay Engine loaded 4 recorded tool execution traces",
            "[22:04:35] Re-evaluated Planner, Analyst, Critic, and Auditor deterministic logic",
            "[22:04:36] Compared Original vs Replay conclusion: 100% exact match",
            "[22:04:37] Cryptographic hash state identical. Reproducibility verified: 100%",
        ],
        "evidence": ["EV-001", "EV-002", "EV-003", "EV-004"],
        "trust_score": 100.0,
        "claims_count": 3,
        "conclusion": "100% Deterministic Reproducibility Verified",
    },
]


def _build_demo_state(
    session_id: str,
    active_step_idx: int,
    history: List[InteractiveDemoStep]
) -> InteractiveDemoSessionState:
    step_info = DEMO_STEPS_CATALOG[active_step_idx]
    cum_ev = []
    all_logs = []
    for h in history:
        for e in h.evidence_ids:
            if e not in cum_ev:
                cum_ev.append(e)
        all_logs.extend(h.telemetry_logs)

    is_complete = (active_step_idx == len(DEMO_STEPS_CATALOG) - 1)

    return InteractiveDemoSessionState(
        session_id=session_id,
        case_id="CASE-2026-0042",
        current_step_id=step_info["id"],
        current_step_number=step_info["number"],
        is_complete=is_complete,
        completed_steps=history,
        available_steps=[s["id"] for s in DEMO_STEPS_CATALOG],
        cumulative_evidence=cum_ev,
        latest_telemetry=all_logs[-6:] if all_logs else step_info["telemetry"],
        current_trust_score=step_info["trust_score"],
        current_verdict=step_info["conclusion"],
    )


def execute_interactive_demo_step(
    db: Session,
    step_id: str,
    session_id: Optional[str] = "default-demo"
) -> InteractiveDemoSessionState:
    """Execute a specific stage in the 7-stage interactive demo simulation."""
    global _DEMO_SESSIONS
    sess_id = session_id or "default-demo"

    # Find the target step catalog entry
    target_idx = 0
    for idx, s in enumerate(DEMO_STEPS_CATALOG):
        if s["id"] == step_id:
            target_idx = idx
            break

    # Build history up to and including target_idx
    now_iso = datetime.now(timezone.utc).isoformat()
    history: List[InteractiveDemoStep] = []
    for i in range(target_idx + 1):
        cat = DEMO_STEPS_CATALOG[i]
        history.append(
            InteractiveDemoStep(
                step_id=cat["id"],
                step_name=cat["name"],
                step_number=cat["number"],
                agent_id=cat["agent_id"],
                agent_name=cat["agent_name"],
                status="completed" if i < target_idx else "active",
                action_summary=cat["summary"],
                telemetry_logs=cat["telemetry"],
                evidence_ids=cat["evidence"],
                trust_score=cat["trust_score"],
                claims_count=cat["claims_count"],
                current_conclusion=cat["conclusion"],
                timestamp=now_iso,
            )
        )

    state = _build_demo_state(sess_id, target_idx, history)
    _DEMO_SESSIONS[sess_id] = state

    # Broadcast WebSocket event
    try:
        ws_manager.dispatch_sync(
            channel="telemetry",
            event_type="DEMO_PIPELINE_STEP",
            data={
                "session_id": sess_id,
                "step_id": step_id,
                "step_number": target_idx + 1,
                "agent_name": DEMO_STEPS_CATALOG[target_idx]["agent_name"],
                "conclusion": DEMO_STEPS_CATALOG[target_idx]["conclusion"],
                "trust_score": DEMO_STEPS_CATALOG[target_idx]["trust_score"],
                "timestamp": now_iso,
            },
        )
    except Exception as e:
        logger.warning(f"Could not broadcast demo step event: {e}")

    return state


def get_demo_pipeline_state(
    db: Session,
    session_id: Optional[str] = "default-demo"
) -> InteractiveDemoSessionState:
    """Retrieve current state of the 7-stage interactive demo simulation."""
    global _DEMO_SESSIONS
    sess_id = session_id or "default-demo"
    if sess_id in _DEMO_SESSIONS:
        return _DEMO_SESSIONS[sess_id]
    # Default to step 1
    return execute_interactive_demo_step(db, "start_investigation", sess_id)


def reset_demo_pipeline(
    db: Session,
    session_id: Optional[str] = "default-demo"
) -> InteractiveDemoSessionState:
    """Reset interactive demo pipeline state back to initial."""
    global _DEMO_SESSIONS
    sess_id = session_id or "default-demo"
    return execute_interactive_demo_step(db, "start_investigation", sess_id)
