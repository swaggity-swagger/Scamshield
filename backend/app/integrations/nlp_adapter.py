from typing import Any, Literal

from app.services.analyzer import analyze_text


Language = Literal["en", "hi", "mr"]


def analyze_message(
    text: str,
    preferred_language: Language = "en",
) -> dict[str, Any]:
    """
    Stable application-level wrapper around the
    multilingual NLP analyzer.
    """

    result = analyze_text(
        text,
        preferred_language=preferred_language,
    )

    if not isinstance(result, dict):
        raise TypeError(
            "NLP analyzer returned a non-dict result."
        )

    return result