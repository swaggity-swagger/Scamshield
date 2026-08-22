from fastapi import FastAPI
from app.api.routes import analysis

app = FastAPI(
    title="ScamSense API",
    description=(
        "Backend API for ScamSense, a multilingual scam detection "
        "and incident-response web application."
    ),
    version="1.0.0",
)

app.include_router(analysis.router)


@app.get("/")
def read_root():
    return {"message": "Welcome to the ScamSense API!"}


@app.get("/health")
def health_check():
    return {"status": "OK"}