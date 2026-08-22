from fastapi import FastAPI

from app.models import AnalyzeTextRequest, AnalyzeTextResponse
from app.services.analyzer import TRANSLATIONS, analyze_text

app = FastAPI(
    title="ScamSense AI/NLP Service",
    version="1.0.0",
    description="Explainable multilingual scam-risk analysis for messages and OCR text.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "scamsense-nlp"}


@app.get("/api/v1/supported-languages")
def supported_languages() -> dict[str, list[str]]:
    return {"languages": list(TRANSLATIONS.keys())}


@app.post("/api/v1/analyze/text", response_model=AnalyzeTextResponse)
def analyze_message(payload: AnalyzeTextRequest) -> dict:
    return analyze_text(payload.text, payload.preferred_language)
