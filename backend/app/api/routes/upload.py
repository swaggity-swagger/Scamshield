from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.services.analysis_service import analyze_message
from app.services.ocr_service import extract_text_from_image


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)


@router.post("/image")
async def upload_image(
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
        extracted_text = extract_text_from_image(image_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not process image: {exc}",
        ) from exc

    if not extracted_text:
        raise HTTPException(
            status_code=400,
            detail="No readable text was found in the image.",
        )

    analysis_result = analyze_message(
        extracted_text,
        language,
    )

    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "language": language,
        "extracted_text": extracted_text,
        "analysis": analysis_result,
    }