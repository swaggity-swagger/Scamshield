from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analysis_result import AnalysisResult
from app.models.evidence import Evidence


def save_analysis(
    db: Session,
    incident_id: int,
    analysis_type: str,
    result: dict[str, Any],
):
    risk_score = result.get("risk_score")
    risk_level = result.get("risk_level")
    confidence = result.get("confidence")

    analysis = AnalysisResult(
        incident_id=incident_id,
        analysis_type=analysis_type,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        result_json=result,
    )

    db.add(analysis)
    db.flush()

    evidence_items = extract_evidence(
        result,
        analysis_type,
    )

    for item in evidence_items:
        db.add(
            Evidence(
                incident_id=incident_id,
                evidence_type=item["evidence_type"],
                title=item["title"],
                description=item["description"],
                severity=item.get("severity"),
                source=analysis_type,
            )
        )

    db.commit()
    db.refresh(analysis)

    return analysis


def extract_evidence(
    result: dict[str, Any],
    source: str,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []

    # NLP-style evidence
    for item in result.get("evidence", []) or []:
        signal = item.get("signal", "Detected signal")
        matched_text = item.get("matched_text", "")
        explanation = item.get(
            "explanation",
            "Suspicious signal detected.",
        )

        description = explanation

        if matched_text:
            description = (
                f"{explanation} "
                f"Matched content: {matched_text}"
            )

        evidence.append(
            {
                "evidence_type": "analysis_signal",
                "title": signal,
                "description": description,
                "severity": item.get("severity"),
            }
        )

    # Cybersecurity-style indicators
    for item in result.get("indicators", []) or []:
        label = (
            item.get("label")
            or item.get("id")
            or "Suspicious indicator"
        )

        description = (
            item.get("description")
            or item.get("explanation")
            or label
        )

        severity = (
            item.get("severity")
            or item.get("risk_level")
        )

        evidence.append(
            {
                "evidence_type": "indicator",
                "title": label,
                "description": description,
                "severity": severity,
            }
        )

    # Combined workflow result
    cybersecurity = result.get(
        "cybersecurity_analysis"
    )

    if isinstance(cybersecurity, dict):
        evidence.extend(
            extract_evidence(
                cybersecurity,
                "cybersecurity",
            )
        )

    ai_response = result.get("ai_response")

    if isinstance(ai_response, dict):
        nlp_assessment = ai_response.get(
            "nlp_assessment"
        )

        if isinstance(nlp_assessment, dict):
            evidence.extend(
                extract_evidence(
                    nlp_assessment,
                    "nlp",
                )
            )

    return evidence


def get_analysis(
    db: Session,
    incident_id: int,
):
    statement = (
        select(AnalysisResult)
        .where(
            AnalysisResult.incident_id == incident_id
        )
        .order_by(
            AnalysisResult.created_at.desc()
        )
    )

    return db.scalars(statement).all()