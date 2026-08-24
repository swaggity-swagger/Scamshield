import io

import pytesseract
from PIL import Image


def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Extract text from an image using Tesseract OCR.
    """

    image = Image.open(io.BytesIO(image_bytes))

    text = pytesseract.image_to_string(image)

    return text.strip()