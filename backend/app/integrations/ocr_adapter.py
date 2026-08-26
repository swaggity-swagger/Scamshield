from typing import Any

from app.services.ocr_service import (
    extract_text_from_image,
)


def extract_image(
    image_bytes: bytes,
) -> dict[str, Any]:
    """
    Application-level wrapper around the OCR service.

    Returns a normalized extraction structure that can be
    consumed by the orchestration layer.
    """

    text = extract_text_from_image(
        image_bytes
    )

    return {
        "text": text or "",
        "urls": [],
        "qr_data": [],
        "upi_ids": [],
    }