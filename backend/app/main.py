from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import auth
from app.api.routes import incidents
from app.api.routes import analysis
from app.api.routes import evidence
from app.api.routes import evidence_upload
from app.api.routes import threat_intelligence
from app.api.routes import reports


app = FastAPI(
    title="ScamSense API",
    description=(
        "Backend API for ScamSense, a multilingual scam detection "
        "and incident-response web application."
    ),
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(analysis.router)
app.include_router(evidence.router)
app.include_router(evidence_upload.router)
app.include_router(threat_intelligence.router)
app.include_router(reports.router)


@app.get("/")
def read_root():
    return {
        "message": "Welcome to the ScamSense API!"
    }


@app.get("/health")
def health_check():
    return {
        "status": "OK"
    }