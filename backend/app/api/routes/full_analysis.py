"""Unified analysis endpoint.

The endpoint accepts an optional uploaded image (which may contain a QR code),
optional plain text, and an optional URL. It orchestrates the existing OCR,
QR‑decoding, NLP (member3) and cybersecurity (member5) services and returns a
single JSON payload that merges the two analyses.
"""

from __future__ import annotations

import re
from typing import Literal, Optional, List

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.schemas.full_analysis import FullAnalysisResponse
from app.services.ocr_service import extract_text_from_image
from app.services.qr_service import decode_qr
from app.services.qr_classifier import classify_qr_content
from app.services.nlp_service import nlp_analyze
from app.services.cyber_service import cyber_analyze

router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)

# Simple URL regex – same as used in member5.analyzer._extract_urls
_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)


@router.post("/full", response_model=FullAnalysisResponse)
async def analyze_full(
    # Optional image file – may contain QR code or text for OCR
    file: Optional[UploadFile] = File(None),
    # Optional raw text (e.g., from a chat box)
    text: Optional[str] = Form(None),
    # Optional explicit URL supplied by the user
    url: Optional[str] = Form(None),
    # Language for NLP – defaults to English
    language: Literal["en", "hi", "mr"] = Form("en"),
) -> FullAnalysisResponse:
    """Run a full analysis pipeline.

    1. If an image is provided, run OCR to get ``ocr_text`` and attempt QR
       decoding. ``qr_payload`` holds the decoded QR content and ``qr_detected``
       flags whether a QR code was present.
    2. Gather all available text for the NLP engine (explicit ``text`` or OCR
       output).
    3. Extract URLs from the text and from any QR payload, combined with an
       explicit ``url`` field, deduped.
    4. Call the member3 NLP analyser and the member5 cybersecurity analyser.
    5. Merge the two results into a unified response.
    """
    # ---------------------------------------------------------------------
    # 1. Process optional image
    # ---------------------------------------------------------------------
    ocr_text: Optional[str] = None
    qr_payload: Optional[str] = None
    qr_detected = False

    if file:
        allowed = {"image/jpeg", "image/png", "image/webp"}
        if file.content_type not in allowed:
            raise HTTPException(
                status_code=400,
                detail="Only JPG, PNG, and WebP images are supported.",
            )
        image_bytes = await file.read()
        # OCR – ignore errors, just keep None if it fails
        try:
            ocr_text = extract_text_from_image(image_bytes)
        except Exception as exc:
            # Log internally; for now we just continue without OCR text
            ocr_text = None
        # QR decode – if it fails we treat as non‑QR
        try:
            qr_payload = decode_qr(image_bytes)
            qr_detected = True
        except Exception:
            qr_payload = None
            qr_detected = False

    # ---------------------------------------------------------------------
    # 2. Determine text for NLP
    # ---------------------------------------------------------------------
    nlp_input_text: Optional[str] = text or ocr_text

    # ---------------------------------------------------------------------
    # 3. Collect URLs from explicit field, OCR text, and QR payload
    # ---------------------------------------------------------------------
    url_candidates: List[str] = []
    if url:
        url_candidates.append(url)
    # Helper to pull URLs from any string source
    def _extract(src: Optional[str]):
        if not src:
            return []
        return _URL_RE.findall(src)

    url_candidates.extend(_extract(nlp_input_text))
    url_candidates.extend(_extract(qr_payload))
    # Deduplicate while preserving order
    seen: set[str] = set()
    urls: List[str] = []
    for u in url_candidates:
        if u not in seen:
            seen.add(u)
            urls.append(u)

    # ---------------------------------------------------------------------
    # 4. Run the two analysis services
    # ---------------------------------------------------------------------
    nlp_result = nlp_analyze(
        nlp_input_text or "",
        preferred_language=language,
    )

    cyber_result: dict = cyber_analyze(
        text=nlp_input_text,
        urls=urls,
        qr_data=qr_payload,
        upi_data=None,
        qr_detected=qr_detected,
    )

    # ---------------------------------------------------------------------
    # 5. Merge results
    # ---------------------------------------------------------------------
    nlp_score = nlp_result.get("risk_score", 0)
    cyber_score = cyber_result.get("risk_score", 0)
    combined_risk_score = max(nlp_score, cyber_score)

    # Resolve combined risk level – ordering from low to critical
    level_order = {"low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": -1}
    nlp_level = nlp_result.get("risk_level", "unknown").lower()
    cyber_level = cyber_result.get("risk_level", "unknown").lower()
    # Choose the higher severity; fallback to unknown if both unknown
    def _severity_key(lvl: str) -> int:
        return level_order.get(lvl, -1)

    combined_risk_level = (
        nlp_level
        if _severity_key(nlp_level) >= _severity_key(cyber_level)
        else cyber_level
    )

    # Union of recommended actions from both services, deduped
    nlp_actions = nlp_result.get("recommended_actions", [])
    cyber_actions = cyber_result.get("recommendations", [])
    combined_actions = list(dict.fromkeys(nlp_actions + cyber_actions))

    response_fields = {**nlp_result, "recommended_actions": combined_actions}

    return FullAnalysisResponse(
        **response_fields,
        nlp_result=nlp_result,
        cyber_result=cyber_result,
        combined_risk_score=combined_risk_score,
        combined_risk_level=combined_risk_level,
    )
