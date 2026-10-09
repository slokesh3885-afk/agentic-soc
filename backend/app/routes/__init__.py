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

__all__ = [
    "investigations_router",
    "evidence_router",
    "tools_router",
    "planner_router",
    "critic_router",
    "auditor_router",
    "trust_score_router",
    "scenario_router",
    "approvals_router",
    "websockets_router",
    "audit_trail_router",
    "dossiers_router",
    "containment_router",
    "replay_router",
    "reports_router",
    "agents_router",
]
