from urllib.parse import urlparse


def classify_qr_content(content: str) -> str:
    """
    Classify decoded QR content as URL, UPI, TEXT, or UNKNOWN.
    """

    content = content.strip()

    if not content:
        return "UNKNOWN"

    # UPI payment QR
    if content.lower().startswith("upi://pay"):
        return "UPI"

    # HTTP/HTTPS URL
    parsed_url = urlparse(content)

    if parsed_url.scheme in {"http", "https"} and parsed_url.netloc:
        return "URL"

    # Any other decoded content
    if content:
        return "TEXT"

    return "UNKNOWN"