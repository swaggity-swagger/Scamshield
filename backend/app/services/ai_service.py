from typing import Any

from app.services.analyzer import analyze_text


def classify_message(
    message: str,
    language: str = "en",
) -> dict[str, Any]:
    result = analyze_text(
        message,
        preferred_language=language,
    )

    indicators = [
        (
            f"{item.signal}: {item.explanation} "
            f"(matched: {item.matched_text})"
        )
        for item in result["evidence"]
    ]

    category = (
        result["scam_categories"][0]
        if result["scam_categories"]
        else "NO_SPECIFIC_CATEGORY"
    )

    return {
        "risk_level": result["risk_level"].upper(),
        "category": category.upper(),
        "confidence": result["confidence"] / 100,
        "indicators": indicators,
        "explanation": result["summary"],
        "recommended_actions": result["recommended_actions"],
    }