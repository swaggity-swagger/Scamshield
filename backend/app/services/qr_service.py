import io

import cv2
import numpy as np


def _decode_with_detector(image: np.ndarray) -> str | None:
    """Try decoding a QR code from an OpenCV image."""
    detector = cv2.QRCodeDetector()

    decoded_text, points, _ = detector.detectAndDecode(image)

    if decoded_text:
        return decoded_text.strip()

    return None


def _preprocess_images(image: np.ndarray) -> list[np.ndarray]:
    """Create several image versions that may be easier to decode."""
    processed_images = []

    # Original image
    processed_images.append(image)

    # Grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    processed_images.append(gray)

    # Upscaled grayscale
    upscaled = cv2.resize(
        gray,
        None,
        fx=2,
        fy=2,
        interpolation=cv2.INTER_CUBIC,
    )
    processed_images.append(upscaled)

    # Otsu threshold
    _, otsu = cv2.threshold(
        upscaled,
        0,
        255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU,
    )
    processed_images.append(otsu)

    # Adaptive threshold
    adaptive = cv2.adaptiveThreshold(
        upscaled,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        11,
        2,
    )
    processed_images.append(adaptive)

    return processed_images


def decode_qr(image_bytes: bytes) -> str:
    """
    Decode a QR code from image bytes.

    Tries the original image and several preprocessed versions.
    Raises ValueError when no readable QR code is found.
    """

    image_array = np.frombuffer(image_bytes, dtype=np.uint8)

    image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

    if image is None:
        raise ValueError("Could not read the uploaded image.")

    processed_images = _preprocess_images(image)

    for processed_image in processed_images:
        result = _decode_with_detector(processed_image)

        if result:
            return result

    raise ValueError(
        "No readable QR code was found in the image."
    )