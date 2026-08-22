"""ScamShield web application and API."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .scamshield.member3.analyzer import analyze_text
from .scamshield.member5 import analyze_input
from .scamshield.workflow import _ai_response, _jsonable, run_scamshield_workflow


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
MAX_IMAGE_BYTES = 10 * 1024 * 1024
ALLOWED_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}

app = FastAPI(title="ScamShield", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class TextAnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
    preferred_language: str = "en"


def _text_result(text: str, language: str) -> dict:
    cybersecurity = _jsonable(analyze_input(text=text))
    return {
        "status": "ok",
        "errors": [],
        "extracted_information": {"source": "text", "text": text, "qr_data": [], "urls": []},
        "cybersecurity_analysis": cybersecurity,
        "ai_response": _ai_response(text, cybersecurity, language, analyze_text),
    }


@app.get("/")
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "scamsense-2.html")


@app.get("/login")
def login() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze/text")
def analyze_text_content(payload: TextAnalysisRequest) -> dict:
    if payload.preferred_language not in {"en", "hi", "mr"}:
        raise HTTPException(status_code=422, detail="preferred_language must be en, hi, or mr")
    return _text_result(payload.text, payload.preferred_language)


@app.post("/api/analyze/image")
async def analyze_image_content(image: UploadFile = File(...), preferred_language: str = "en") -> dict:
    suffix = Path(image.filename or "").suffix.lower()
    if suffix not in ALLOWED_IMAGE_SUFFIXES:
        raise HTTPException(status_code=415, detail="Upload a PNG, JPG, JPEG, WEBP, or BMP image.")
    if preferred_language not in {"en", "hi", "mr"}:
        raise HTTPException(status_code=422, detail="preferred_language must be en, hi, or mr")

    content = await image.read()
    if not content or len(content) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image must be between 1 byte and 10 MB.")

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
            temp_file.write(content)
            temp_path = Path(temp_file.name)
        return run_scamshield_workflow(temp_path, preferred_language)
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)
