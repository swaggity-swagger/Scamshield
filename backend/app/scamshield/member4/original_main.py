"""Member 4 OCR and QR extraction, refactored from the supplied script.

The OpenCV/Tesseract processing steps are unchanged; this module exposes them
as a callable function instead of processing one hard-coded demo file on import.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>'\"]+", re.IGNORECASE)
UPI_RE = re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}[a-zA-Z0-9]*\b")


def extract_from_image(image_path: str | Path, tesseract_cmd: str | None = None) -> dict[str, Any]:
    """Extract OCR text, QR payloads, URLs, and UPI IDs from a screenshot."""
    import cv2
    import pytesseract

    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Image file was not found: {path}")

    configured_tesseract = tesseract_cmd or r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if Path(configured_tesseract).is_file():
        pytesseract.pytesseract.tesseract_cmd = configured_tesseract

    image = cv2.imread(str(path))
    if image is None:
        raise ValueError(f"Image could not be read: {path}")

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray = cv2.resize(gray, None, fx=2, fy=2)
    _, threshold = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)
    text = pytesseract.image_to_string(threshold).strip()

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image)
    qr_data = [data] if data else []
    searchable_content = "\n".join([text, *qr_data])
    urls = [match.group(0).rstrip(".,)") for match in URL_RE.finditer(searchable_content)]
    upi_ids = list(dict.fromkeys(UPI_RE.findall(searchable_content)))

    return {
        "image_path": str(path),
        "text": text,
        "qr_detected": points is not None,
        "qr_data": qr_data,
        "urls": list(dict.fromkeys(urls)),
        "upi_ids": upi_ids,
    }
