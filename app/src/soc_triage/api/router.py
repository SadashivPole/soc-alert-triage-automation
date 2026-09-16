from fastapi import APIRouter

from .alerts import router as alerts_router
from .correlations import router as correlations_router
from .explanations import router as explanations_router
from .feedback import router as feedback_router
from .health import router as health_router
from .incident_assignment import router as incident_assignment_router
from .incident_evidence import router as incident_evidence_router
from .incident_notes import router as incident_notes_router
from .incident_thehive import router as incident_thehive_router
from .incidents import router as incidents_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(alerts_router)
api_router.include_router(explanations_router)
api_router.include_router(correlations_router)
api_router.include_router(feedback_router)
api_router.include_router(incidents_router)
api_router.include_router(incident_assignment_router)
api_router.include_router(incident_notes_router)
api_router.include_router(incident_evidence_router)
api_router.include_router(incident_thehive_router)
