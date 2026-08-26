from typing import Any

from app.services.qr_service import decode_qr
from app.services.qr_classifier import classify_qr_content


def decode_image_qr(
    image_bytes: bytes,
) -> dict[str, Any]:
    """
    Decode a QR code from image bytes and classify
    the decoded payload.

    Returns a normalized structure for the
    ScamShield orchestration layer.
    """

    payload = decode_qr(
        image_bytes
    )

    qr_type = classify_qr_content(
        payload
    )

    result: dict[str, Any] = {
        "qr_detected": True,
        "qr_data": [payload],
        "urls": [],
        "upi_ids": [],
        "text": "",
        "qr_type": qr_type,
    }

    if qr_type == "URL":
        result["urls"] = [payload]

    elif qr_type == "UPI":
        result["upi_ids"] = [payload]

    elif qr_type == "TEXT":
        result["text"] = payload

    else:
        result["text"] = payload

    return result