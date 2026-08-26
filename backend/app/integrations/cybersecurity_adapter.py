from typing import Any

from app.integrations.cybersecurity.analyzer import analyze_input


def analyze_security(
    text: str | None = None,
    urls: list[str] | None = None,
    qr_data: list[str] | None = None,
    upi_data: dict[str, Any] | str | None = None,
) -> dict[str, Any]:
    """
    Stable application-level wrapper around the cybersecurity engine.
    """

    result = analyze_input(
        text=text,
        urls=urls,
        qr_data=qr_data,
        upi_data=upi_data,
    )

    if not isinstance(result, dict):
        raise TypeError(
            "Cybersecurity analyzer must return a dictionary."
        )

    return result