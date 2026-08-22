"""Backend-ready orchestration for the Member 4 -> 5 -> 3 ScamShield flow."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .member3.analyzer import analyze_text
from .member4 import extract_from_image
from .member5 import analyze_input


def _jsonable(value: Any) -> Any:
    """Convert Pydantic values from Member 3 into plain JSON-compatible data."""
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump())
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _ai_response(text: str, cybersecurity: dict[str, Any], language: str, ai_service: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    """Use Member 3 for language-aware context while retaining Member 5 as truth."""
    nlp_assessment = _jsonable(ai_service(text, language))
    return {
        "available": True,
        "detected_language": nlp_assessment["detected_language"],
        "summary": nlp_assessment["summary"],
        "nlp_assessment": nlp_assessment,
        "cybersecurity_context": {
            "risk_score": cybersecurity["risk_score"],
            "risk_level": cybersecurity["risk_level"],
            "scam_type": cybersecurity["scam_type"],
            "indicator_labels": [item["label"] for item in cybersecurity["indicators"]],
        },
        "recommended_actions": cybersecurity["recommendations"],
        "risk_source": "member5_cybersecurity",
    }


def run_scamshield_workflow(
    image_path: str | Path | None,
    preferred_language: str = "en",
    *,
    extraction_service: Callable[[str | Path], dict[str, Any]] = extract_from_image,
    cybersecurity_service: Callable[..., dict[str, Any]] = analyze_input,
    ai_service: Callable[..., dict[str, Any]] = analyze_text,
) -> dict[str, Any]:
    """Run screenshot extraction, cybersecurity analysis, and multilingual NLP.

    This is a standalone interface for a future backend; it creates no HTTP,
    database, or frontend dependency.  Services are injectable for integration
    testing and controlled deployment fallbacks.
    """
    result: dict[str, Any] = {
        "status": "ok",
        "errors": [],
        "extracted_information": None,
        "cybersecurity_analysis": None,
        "ai_response": None,
    }
    if not image_path:
        result.update(status="invalid_input")
        result["errors"].append({"stage": "member4_extraction", "message": "image_path is required."})
        return result

    try:
        extracted = _jsonable(extraction_service(image_path))
        result["extracted_information"] = extracted
    except Exception as error:
        result.update(status="failed")
        result["errors"].append({"stage": "member4_extraction", "message": str(error)})
        return result

    try:
        cybersecurity = _jsonable(cybersecurity_service(
            text=extracted.get("text") or None,
            urls=extracted.get("urls"),
            qr_data=extracted.get("qr_data"),
            upi_data=extracted.get("upi_ids"),
            qr_detected=bool(extracted.get("qr_detected")),
        ))
        result["cybersecurity_analysis"] = cybersecurity
    except Exception as error:
        result.update(status="partial")
        result["errors"].append({"stage": "member5_cybersecurity", "message": str(error)})
        return result

    try:
        result["ai_response"] = _ai_response(
            extracted.get("text", ""), cybersecurity, preferred_language, ai_service
        )
    except Exception as error:
        result.update(status="partial")
        result["ai_response"] = {"available": False, "message": "AI/NLP response is unavailable.", "risk_source": "member5_cybersecurity"}
        result["errors"].append({"stage": "member3_ai_nlp", "message": str(error)})

    return _jsonable(result)
