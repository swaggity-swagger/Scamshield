from pathlib import Path

from app.services.ocr_service import extract_text_from_image


def test_ocr_extracts_text_from_screenshot():
    image_path = Path("test_ocr.png")

    assert image_path.exists(), (
        "test_ocr.png not found in backend directory"
    )

    image_bytes = image_path.read_bytes()

    extracted_text = extract_text_from_image(image_bytes)

    assert extracted_text
    assert isinstance(extracted_text, str)
    assert len(extracted_text.strip()) > 0