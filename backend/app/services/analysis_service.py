from app.services.ai_service import classify_message


def analyze_message(
    message: str,
    language: str = "en",
) -> dict:
    result = classify_message(
        message,
        language,
    )

    return {
        "language": language,
        **result,
    }