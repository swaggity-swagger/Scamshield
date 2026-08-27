from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import analysis
from app.api.routes import upload
from app.api.routes import qr
from app.api.routes.full_analysis import router as full_router

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
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
        "http://127.0.0.1:5502",
        "http://localhost:5502",
    ],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.include_router(analysis.router)
app.include_router(upload.router)
app.include_router(qr.router)
# New unified analysis endpoint
app.include_router(full_router)


@app.get("/")
def read_root():
    return {"message": "Welcome to the ScamSense API!"}


@app.get("/health")
def health_check():
    return {"status": "OK"}
