from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.services.analysis_service import analyze_message
from app.services.qr_classifier import classify_qr_content
from app.services.qr_service import decode_qr
from app.services.url_service import analyze_url


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)


@router.post("/qr")
async def analyze_qr(
    file: UploadFile = File(...),
    language: Literal["en", "hi", "mr"] = Form("en"),
):
    allowed_types = {
        "image/jpeg",
        "image/png",
        "image/webp",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Only JPG, PNG, and WebP images are supported.",
        )

    image_bytes = await file.read()

    try:
        decoded_content = decode_qr(image_bytes)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    content_type = classify_qr_content(decoded_content)

    if content_type == "URL":
        analysis = analyze_url(
            decoded_content,
            language,
        )

    elif content_type == "TEXT":
        analysis = analyze_message(
            decoded_content,
            language,
        )

    elif content_type == "UPI":
        analysis = {
            "risk_level": "UNKNOWN",
            "category": "UPI_PAYMENT",
            "confidence": None,
            "indicators": [],
            "explanation": (
                "This QR code contains a UPI payment request. "
                "Payment details require further verification."
            ),
            "recommended_actions": [
                "Verify the recipient before making a payment",
                "Never approve a payment request you did not initiate",
                "Do not share your UPI PIN",
            ],
        }

    else:
        analysis = {
            "risk_level": "UNKNOWN",
            "category": "UNKNOWN_QR",
            "confidence": None,
            "indicators": [],
            "explanation": "The QR content could not be classified.",
            "recommended_actions": [
                "Do not act on the QR content until it is verified",
            ],
        }

    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "language": language,
        "decoded_content": decoded_content,
        "qr_content_type": content_type,
        "analysis": analysis,
    }
