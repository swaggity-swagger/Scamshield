from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.analysis import router as analysis_router
from app.api.routes.auth import router as auth_router
from app.api.routes.chat import router as chat_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.evidence import router as evidence_router
from app.api.routes.evidence_upload import (
    router as evidence_upload_router,
)
from app.api.routes.incidents import router as incidents_router
from app.api.routes.reports import router as reports_router
from app.api.routes.threat_intelligence import (
    router as threat_intelligence_router,
)
from app.api.routes.timeline import router as timeline_router


app = FastAPI(
    title="ScamSense API",
    description=(
        "Backend API for ScamSense, a multilingual scam detection "
        "and incident-response web application."
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROUTES
# ============================================================

app.include_router(
    auth_router,
)

app.include_router(
    incidents_router,
)

app.include_router(
    analysis_router,
)

app.include_router(
    evidence_router,
)

app.include_router(
    evidence_upload_router,
)

app.include_router(
    threat_intelligence_router,
)

app.include_router(
    reports_router,
)

app.include_router(
    chat_router,
)

app.include_router(
    timeline_router,
)

app.include_router(
    dashboard_router,
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def read_root():
    return {
        "message": "Welcome to the ScamSense API!"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "OK"
    }