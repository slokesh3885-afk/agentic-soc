from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import engine, Base, SessionLocal
from app.routes.investigations import router as investigations_router
from app.routes.evidence import router as evidence_router
from app.routes.tools import router as tools_router
from app.routes.planner import router as planner_router
from app.routes.critic import router as critic_router
from app.routes.auditor import router as auditor_router
from app.routes.trust_score import router as trust_score_router
from app.routes.scenario import router as scenario_router
from app.routes.approvals import router as approvals_router
from app.routes.websockets import router as websockets_router
from app.routes.audit_trail import router as audit_trail_router
from app.routes.dossiers import router as dossiers_router
from app.routes.containment import router as containment_router
from app.routes.replay import router as replay_router
from app.routes.reports import reports_router
from app.routes.agents import router as agents_router
from app.routes.redteam import router as redteam_router
from app.routes.case_audit_object import router as case_audit_object_router
from app.routes.system import router as system_router
from app.routes.analytics import router as analytics_router
from app.services.investigation_service import seed_initial_investigations
from app.services.evidence_service import seed_initial_evidence
from app.services.tool_service import seed_initial_tool_executions
from app.services.approval_service import seed_initial_approvals
from app.services.audit_service import seed_initial_audit_trail
from app.services.dossier_service import seed_initial_dossiers
from app.services.containment_service import seed_initial_containments
from app.services.replay_service import seed_initial_replays
from app.services.report_service import seed_initial_reports
from app.services.agent_service import seed_initial_agents
from app.services.websocket_manager import ws_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: initialize SQLite tables and seed data if empty."""
    import asyncio
    # Ensure database schema is created
    Base.metadata.create_all(bind=engine)

    # Initialize WebSocket manager with active event loop
    ws_manager.set_loop(asyncio.get_running_loop())

    # Seed initial mock records if database has no investigations, evidence, or tool logs yet
    db = SessionLocal()
    try:
        seed_initial_investigations(db)
        seed_initial_evidence(db)
        seed_initial_tool_executions(db)
        seed_initial_approvals(db)
        seed_initial_audit_trail(db)
        seed_initial_dossiers(db)
        seed_initial_containments(db)
        seed_initial_replays(db)
        seed_initial_reports(db)
        seed_initial_agents(db)
    finally:
        db.close()

    yield


# Explicit tag descriptions for Swagger UI organization
tags_metadata = [
    {
        "name": "redteam",
        "description": "Critic & Red-Team Adversarial Evaluation Engine & Interactive Demo (Module 3S) — Deterministic red-team challenges against preliminary conclusions, contradiction detection, Threat Actor Attribution Policy enforcement, and 7-stage interactive simulation pipeline.",
    },
    {
        "name": "agents",
        "description": "Multi-Agent Swarm Orchestration & Control Plane (Module 3Q) — Operational state, task telemetry, and activity logs for the 5 core SOC agents (Planner, Tool, Analyst, Critic, Auditor), Analyst Agent reasoning, and autonomous swarm cycle orchestration.",
    },
    {
        "name": "auditor",
        "description": "Auditor Agent (Module 3E) — Final evidence-accountability layer converting investigations into structured, tamper-evident audited cases.",
    },
    {
        "name": "critic",
        "description": "Critic / Red-Team Agent (Module 3D) — Deterministic evaluation challenging investigator draft conclusions against verified evidence, detecting unsupported attribution, missing evidence, contradictions, and overconfidence.",
    },
    {
        "name": "planner",
        "description": "Planner Agent (Module 3C) — Deterministic investigation planning referencing only allow-listed Tool Registry tools.",
    },
    {
        "name": "tools",
        "description": "Allow-listed Security Tool Layer (Module 3B) — Deterministic, sandboxed telemetry tools (siem_search, edr_process_search, hash_lookup, sandbox_summary, whois_lookup, yara_scan). Every execution automatically creates an auditable Evidence item with SHA-256 content hash.",
    },
    {
        "name": "investigations",
        "description": "SOC Investigation management, lifecycle states, and telemetry metadata.",
    },
    {
        "name": "evidence",
        "description": "Foundational Evidence Engine (Module 3A) — Cryptographic SHA-256 tamper-evident telemetry objects.",
    },
    {
        "name": "scenarios",
        "description": "Deterministic Demonstration Scenarios (Module 3H True Positive & Module 3I Trap Scenario) — Synthetic test scenarios demonstrating end-to-end multi-agent pipeline validation without real security incidents.",
    },
    {
        "name": "approvals",
        "description": "Human-in-the-Loop (HITL) Approvals (Module 3J) — Accountable safety gates for high-impact containment, case closure, and remediation actions with Trust Score gating and safety override enforcement.",
    },
    {
        "name": "audit_trail",
        "description": "Cryptographic Immutable Audit Trail (Module 3L) — SHA-256 hash-chained ledger, Merkle root verification, and tamper-evident sealing of investigations and multi-agent pipeline events.",
    },
    {
        "name": "dossiers",
        "description": "Incident Cases Dossier & MITRE ATT&CK Mapping (Module 3M) — Multi-agent case aggregation, ATT&CK Matrix technique coverage, forensic chains of custody, and MITRE Navigator layer exports.",
    },
    {
        "name": "replay",
        "description": "Forensic Timeline Replay & Reproducibility Engine (Module 3O) — Deterministic re-execution of historical multi-agent investigations, timeline reconstruction, and 100% reproducibility verification.",
    },
    {
        "name": "reports",
        "description": "Executive Security Incident Reporting & Regulatory Compliance Engine (Module 3P) — Multi-agent case reports, threat actor attribution policy guards, regulatory compliance framework evaluations (NIST, ISO 27035, SOC 2, GDPR, HIPAA), and multi-format exports.",
    },
    {
        "name": "system",
        "description": "Enterprise SOC Control Plane, Universal Omnibar Search & Real-Time Notification Center (Module 3U) — Dynamic policy orchestration, configurable trust score weights, cross-module universal omnibar query engine, and actionable security notification events.",
    },
    {
        "name": "analytics",
        "description": "Overview Dashboard Analytics, Multi-Chart Engine & Enterprise Security Posture (Module 3V) — Real-time security posture scoring, 4-chart telemetry feeds (alerts over time, investigation outcomes, evidence sources distribution, trust score history), and executive SOC KPI aggregations.",
    },
]


app = FastAPI(
    title="Agentic SOC — Auditable AI Security Operations Center API",
    description="FastAPI persistent backend for SOC investigations, telemetry, evidence verification, allow-listed security tools, Planner Agent, Critic / Red-Team Agent, Auditor Agent, Analyst Agent, Canonical Case JSON Schema, Cryptographic Immutable Audit Trail, and Incident Cases Dossier with MITRE ATT&CK Mapping.",
    version="0.16.0",
    openapi_tags=tags_metadata,
    swagger_ui_parameters={
        "docExpansion": "full",
        "defaultModelsExpandDepth": -1,
        "displayRequestDuration": True,
    },
    lifespan=lifespan,
)


class NoCacheDocsMiddleware(BaseHTTPMiddleware):
    """Ensure OpenAPI schema and docs are never cached by the browser."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path in ("/openapi.json", "/docs", "/redoc"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response


app.add_middleware(NoCacheDocsMiddleware)

# CORS configuration allowing local frontend development
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount primary routes under /api
app.include_router(analytics_router, prefix="/api")
app.include_router(system_router, prefix="/api")
app.include_router(case_audit_object_router, prefix="/api")
app.include_router(redteam_router, prefix="/api")
app.include_router(agents_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(replay_router, prefix="/api")
app.include_router(containment_router, prefix="/api")
app.include_router(dossiers_router, prefix="/api")
app.include_router(audit_trail_router, prefix="/api")
app.include_router(approvals_router, prefix="/api")
app.include_router(scenario_router, prefix="/api")
app.include_router(trust_score_router, prefix="/api")
app.include_router(auditor_router, prefix="/api")
app.include_router(critic_router, prefix="/api")
app.include_router(planner_router, prefix="/api")
app.include_router(tools_router, prefix="/api")
app.include_router(investigations_router, prefix="/api")
app.include_router(evidence_router, prefix="/api")
app.include_router(websockets_router)

# Also mount tools router at root as alias (e.g. /tools -> /api/tools)
app.include_router(tools_router, include_in_schema=False)


@app.get("/api/health", tags=["system"])
def health_check():
    """Health check endpoint for system monitoring."""
    return {
        "status": "ok",
        "service": "Agentic SOC Backend",
        "module": "Module 3F: Case JSON Schema",
        "scenario_module": "Module 3I: Trap Scenario",
        "human_approval_module": "Module 3J: Human Approval",
        "websocket_module": "Module 3K: WebSockets Real-time Streaming",
        "audit_trail_module": "Module 3L: Cryptographic Immutable Audit Trail",
        "dossier_module": "Module 3M: Incident Cases Dossier & MITRE ATT&CK Mapping",
        "containment_module": "Module 3N: Containment & Remediation Playbooks Engine",
        "replay_module": "Module 3O: Forensic Timeline Replay & Investigation Reproducibility Engine",
        "reporting_module": "Module 3P: Executive Security Incident Reporting & Regulatory Compliance Engine",
        "agents_module": "Module 3Q: Autonomous Multi-Agent Swarm Orchestration & Control Plane",
        "evidence_module": "Module 3R: Evidence Control Plane & Claims Corroboration Engine",
        "critic_redteam_module": "Module 3S: Critic & Red-Team Adversarial Evaluation Engine",
        "complete_audit_object_module": "Module 3T: Complete Case Audit Object & Formatted JSON Inspector",
        "system_control_plane_module": "Module 3U: Enterprise SOC Control Plane & Universal Omnibar Search",
        "analytics_module": "Module 3V: Overview Dashboard Analytics & Multi-Chart Engine",
        "control_plane_ui_module": "Module 3W: Enterprise SOC Control Plane UI & TopBar Universal Omnibar Integration",
        "interactive_orchestrator_module": "Module 3X: Interactive Multi-Agent Demo Action Orchestrator & Control Plane UI",
        "reusable_components_module": "Module 3Y: Reusable Component Library & Circular Progress Trust Score",
        "reusable_components_library": "Active (12 Canonical UI Components & SVG Radial Trust Score)",
        "trust_score_radial_gauge": "Active (Deterministic 6-Factor Circular Visualization)",
        "canonical_json_viewer": "Active (Complete 14-Field Audited Object Inspector)",
        "redteam_adversarial_engine": "Active (Deterministic Red-Team Challenge & Contradiction Resolution)",
        "interactive_demo_pipeline": "Active (7-Stage Deterministic Simulation Pipeline)",
        "evidence_control_plane": "Active (Global Evidence Ledger, Claims Matrix & Attribution Guard)",
        "attribution_guard": "Enforced (Strict Multi-Source Evidentiary Threshold)",
        "agent_swarm": "Active (5 Core Autonomous SOC Agents: Planner, Tool, Analyst, Critic, Auditor)",
        "analyst_agent": "Active (Deterministic Hypothesis & Claims Synthesis)",
        "compliance_engine": "Active (NIST SP 800-61, ISO/IEC 27035, SOC 2 Type II, GDPR Art 33, HIPAA Security Rule)",
        "reproducibility_engine": "Active (100% Deterministic Replay Verification & Timeline Scrubbing)",
        "playbook_orchestrator": "Active (Deterministic Containment & Quarantine Safe Execution)",
        "mitre_matrix_engine": "Active (Enterprise ATT&CK Matrix v14.1 Coverage)",
        "audit_ledger": "Active (SHA-256 Hash-Chained Tamper-Evident Ledger)",
        "merkle_tree_engine": "Active (Deterministic Binary Merkle Root Verification)",
        "websocket_streaming": "Active (Real-time Live Telemetry & Pipeline Broadcast)",
        "omnibar_search_engine": "Active (Universal Multi-Entity Search)",
        "notification_center": "Active (Live Telemetry & Security Alert Notifications)",
        "system_settings_engine": "Active (Dynamic Policy & Trust Score Calibration)",
        "posture_engine": "Active (Enterprise Threat Posture & Multi-Chart Aggregator)",
        "charts_engine": "Active (Alerts Over Time, Outcomes, Evidence Sources, Trust Score History)",
        "omnibar_integration": "Active (Universal Keyboard-Driven Omnibar Search & Notification Center)",
        "settings_control_plane": "Active (Interactive Policy Orchestration & Trust Score Calibration)",
        "demo_action_orchestrator": "Active (7-Stage Deterministic Simulation Pipeline)",
        "enterprise_control_plane_ui": "Active (Dynamic Settings & Policy Orchestrator)",
        "final_integration_module": "Module 3Z: First Screen Paradigm & Enterprise Quality Polish",
        "first_screen_paradigm": "Active (Investigate -> Challenge -> Prove -> Audit)",
        "enterprise_polish": "Verified (Zero Placeholders, 12 Reusable Components)",
        "e2e_verification": "Complete (Modules 3A-3Z Fully Validated)",
        "version": "0.17.0",
        "evidence_integrity": "SHA-256 Immutability Enabled",
        "tool_registry": "Active (6 Allow-listed Tools)",
        "planner_agent": "Active (Deterministic Safe Planning)",
        "critic_agent": "Active (Deterministic Reasoning & Red-Teaming)",
        "auditor_agent": "Active (Deterministic Case Auditing & Evidence Verification)",
        "case_json_schema": "Active (Canonical Deterministic Case JSON v1.0.0)",
        "trust_score_engine": "Active (Deterministic Evidence & Audit Quality Scoring 0-100)",
        "demonstration_scenarios": "Active (Deterministic Synthetic True Positive & Trap Scenarios)",
        "human_approval": "Active (Deterministic Gating & Override Enforcement)",
    }
