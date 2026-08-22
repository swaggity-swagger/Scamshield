"""FastAPI entry point for the ScamShield demonstration application."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from scamshield.member3.analyzer import analyze_text
from scamshield.member5 import analyze_input
from scamshield.workflow import run_scamshield_workflow


ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend" / "index.html"
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/bmp"}

app = FastAPI(title="ScamShield", version="1.0.0")


class ContentRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    kind: str = Field(default="message", pattern="^(message|url)$")


def _threat_level(value: str | None) -> str:
    """Present the existing risk engine's VERY HIGH label as CRITICAL in the UI."""
    return "CRITICAL" if value == "VERY HIGH" else (value or "LOW")


def _category(value: str | None) -> str:
    return (value or "NORMAL_OR_UNKNOWN").replace("_", " ").title()


def _public_result(workflow: dict[str, Any]) -> dict[str, Any]:
    """Adapt the existing workflow output for the frontend without changing analysis."""
    extracted = workflow.get("extracted_information") or {}
    cybersecurity = workflow.get("cybersecurity_analysis") or {}
    ai_response = workflow.get("ai_response") or {}
    nlp = ai_response.get("nlp_assessment") or {}
    indicators = cybersecurity.get("indicators") or []
    return {
        "status": workflow.get("status", "failed"),
        "warnings": [error.get("message", "Analysis could not be completed.") for error in workflow.get("errors", [])],
        "threat_level": _threat_level(cybersecurity.get("risk_level")),
        "raw_threat_level": cybersecurity.get("risk_level"),
        "category": _category(cybersecurity.get("scam_type")),
        "risk_score": cybersecurity.get("risk_score", 0),
        "extracted_text": extracted.get("text", ""),
        "qr_detected": bool(extracted.get("qr_detected")),
        "qr_data": extracted.get("qr_data", []),
        "urls": extracted.get("urls", []),
        "suspicious_elements": indicators,
        "explanation": ai_response.get("summary") or nlp.get("summary") or "No additional explanation was available.",
        "recommended_actions": cybersecurity.get("recommendations", []),
        "safety_guidance": nlp.get("recommended_actions", []),
    }


def _content_result(text: str) -> dict[str, Any]:
    """Use existing Member 5 and Member 3 services for typed text or URLs."""
    cybersecurity = analyze_input(text=text)
    nlp = analyze_text(text)
    workflow_like = {
        "status": "ok",
        "errors": [],
        "extracted_information": {"text": text, "qr_detected": False, "qr_data": [], "urls": []},
        "cybersecurity_analysis": cybersecurity,
        "ai_response": {"summary": nlp["summary"], "nlp_assessment": nlp},
    }
    return _public_result(workflow_like)


@app.get("/", include_in_schema=False)
def homepage() -> FileResponse:
    return FileResponse(FRONTEND)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze/content")
def analyze_content(payload: ContentRequest) -> dict[str, Any]:
    try:
        return _content_result(payload.text)
    except Exception as error:
        raise HTTPException(status_code=500, detail="The content could not be analyzed. Please try again.") from error


@app.post("/api/analyze/image")
def analyze_image(image: UploadFile = File(...)) -> dict[str, Any]:
    if image.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=415, detail="Upload a PNG, JPG, WEBP, or BMP image.")

    suffix = Path(image.filename or "upload.png").suffix or ".png"
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="scamshield_", suffix=suffix, delete=False) as temporary_file:
            shutil.copyfileobj(image.file, temporary_file)
            temp_path = Path(temporary_file.name)
        workflow = run_scamshield_workflow(temp_path)
        if workflow.get("status") == "failed":
            raise HTTPException(
                status_code=422,
                detail="We could not analyze this image. Check that the image is readable and Tesseract OCR is installed.",
            )
        return _public_result(workflow)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=422, detail="We could not read this image. Try a clear PNG or JPG screenshot.") from error
    finally:
        image.file.close()
        if temp_path and temp_path.exists():
            temp_path.unlink()
