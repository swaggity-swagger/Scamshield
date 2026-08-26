from pathlib import Path

from app.services.qr_classifier import classify_qr_content
from app.services.qr_service import decode_qr


def test_qr_text_decoding():
    image_path = Path("test_qr_text.png")

    assert image_path.exists(), "test_qr_text.png not found"

    decoded = decode_qr(image_path.read_bytes())

    assert decoded
    assert "bank account" in decoded.lower()
    assert "otp" in decoded.lower()


def test_qr_text_classification():
    content = (
        "Your bank account will be blocked today. "
        "Send your OTP immediately."
    )

    result = classify_qr_content(content)

    assert result == "TEXT"


def test_qr_hindi_decoding():
    image_path = Path("test_qr_hi.png")

    assert image_path.exists(), "test_qr_hi.png not found"

    decoded = decode_qr(image_path.read_bytes())

    assert decoded
    assert "otp" in decoded.lower()


def test_qr_marathi_decoding():
    image_path = Path("test_qr_mr.png")

    assert image_path.exists(), "test_qr_mr.png not found"

    decoded = decode_qr(image_path.read_bytes())

    assert decoded
    assert "otp" in decoded.lower()