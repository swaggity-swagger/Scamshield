from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analysis_result import AnalysisResult
from app.models.evidence import Evidence
from app.models.incident import Incident
from app.models.threat_finding import ThreatFinding
from app.models.timeline import Timeline


def build_incident_context(
    db: Session,
    incident_id: int,
    user_id: int,
) -> str | None:
    """
    Build complete incident-specific context for the chatbot.

    The incident must belong to the authenticated user.

    Returns:
        JSON string containing incident, analysis, evidence,
        threat findings, timeline and recommendations.

        None is returned when the incident does not exist
        or does not belong to the user.
    """

    # =========================================================
    # INCIDENT + OWNERSHIP
    # =========================================================

    incident = db.scalar(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.user_id == user_id,
        )
    )

    if incident is None:
        return None

    # =========================================================
    # ANALYSIS
    # =========================================================

    analyses = db.scalars(
        select(AnalysisResult)
        .where(
            AnalysisResult.incident_id
            == incident_id
        )
        .order_by(
            AnalysisResult.created_at.desc()
        )
    ).all()

    # =========================================================
    # EVIDENCE
    # =========================================================

    evidence = db.scalars(
        select(Evidence)
        .where(
            Evidence.incident_id
            == incident_id
        )
        .order_by(
            Evidence.created_at.desc()
        )
    ).all()

    # =========================================================
    # THREAT FINDINGS
    # =========================================================

    threats = db.scalars(
        select(ThreatFinding)
        .where(
            ThreatFinding.incident_id
            == incident_id
        )
        .order_by(
            ThreatFinding.created_at.desc()
        )
    ).all()

    # =========================================================
    # TIMELINE
    # =========================================================

    timeline = db.scalars(
        select(Timeline)
        .where(
            Timeline.incident_id
            == incident_id
        )
        .order_by(
            Timeline.event_time.desc()
        )
    ).all()

    # =========================================================
    # LATEST ANALYSIS
    # =========================================================

    latest_analysis = (
        analyses[0]
        if analyses
        else None
    )

    latest_result = {}

    if (
        latest_analysis is not None
        and latest_analysis.result_json
    ):
        latest_result = (
            latest_analysis.result_json
        )

    # =========================================================
    # RECOMMENDATIONS
    # =========================================================

    recommendations = (
        latest_result.get(
            "recommended_actions"
        )
        or latest_result.get(
            "recommendations"
        )
        or []
    )

    if isinstance(
        recommendations,
        str,
    ):
        recommendations = [
            recommendations
        ]

    # =========================================================
    # CONTEXT
    # =========================================================

    context = {
        "incident": {
            "id": incident.id,
            "type": incident.incident_type,
            "amount": incident.amount,
            "transaction_id": (
                incident.transaction_id
            ),
            "payment_method": (
                incident.payment_method
            ),
            "description": (
                incident.description
            ),
            "incident_date": (
                incident.incident_date.isoformat()
                if incident.incident_date
                else None
            ),
            "status": incident.status,
            "analysis_category": (
                incident.analysis_category
            ),
            "analysis_risk_level": (
                incident.analysis_risk_level
            ),
            "analysis_summary": (
                incident.analysis_summary
            ),
            "created_at": (
                incident.created_at.isoformat()
                if incident.created_at
                else None
            ),
            "updated_at": (
                incident.updated_at.isoformat()
                if incident.updated_at
                else None
            ),
        },

        "latest_analysis": (
            {
                "id": latest_analysis.id,
                "type": (
                    latest_analysis.analysis_type
                ),
                "risk_score": (
                    latest_analysis.risk_score
                ),
                "risk_level": (
                    latest_analysis.risk_level
                ),
                "confidence": (
                    latest_analysis.confidence
                ),
                "result": latest_result,
            }
            if latest_analysis
            else None
        ),

        "analysis_history": [
            {
                "id": item.id,
                "type": item.analysis_type,
                "risk_score": item.risk_score,
                "risk_level": item.risk_level,
                "confidence": item.confidence,
                "result": item.result_json,
                "created_at": (
                    item.created_at.isoformat()
                    if item.created_at
                    else None
                ),
            }
            for item in analyses[:10]
        ],

        "evidence": [
            {
                "id": item.id,
                "evidence_type": (
                    item.evidence_type
                ),
                "title": item.title,
                "description": (
                    item.description
                ),
                "severity": item.severity,
                "source": item.source,
                "filename": item.filename,
                "sha256": item.sha256,
            }
            for item in evidence[:20]
        ],

        "threat_findings": [
            {
                "id": item.id,
                "indicator": item.indicator,
                "indicator_type": (
                    item.indicator_type
                ),
                "source": item.source,
                "verdict": item.verdict,
                "confidence": (
                    item.confidence
                ),
                "summary": item.summary,
            }
            for item in threats[:20]
        ],

        "timeline": [
            {
                "id": item.id,
                "event_time": (
                    item.event_time.isoformat()
                    if item.event_time
                    else None
                ),
                "event_type": item.event_type,
                "description": (
                    item.description
                ),
            }
            for item in timeline[:20]
        ],

        "recommended_actions": recommendations,
    }

    return json.dumps(
        context,
        ensure_ascii=False,
        default=str,
    )


def extract_chat_risk_context(
    incident_context: str | None,
) -> tuple[str | None, list[str]]:
    """
    Extract concise risk information and suggested actions
    from the JSON incident context.

    Returns:
        risk_context:
            Human-readable risk summary for the frontend.

        suggested_actions:
            Recommended actions extracted from the
            latest stored ScamShield analysis.
    """

    if not incident_context:
        return None, []

    try:
        context = json.loads(
            incident_context
        )
    except (
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None, []

    incident = (
        context.get("incident")
        or {}
    )

    latest_analysis = (
        context.get(
            "latest_analysis"
        )
        or {}
    )

    risk_level = (
        latest_analysis.get(
            "risk_level"
        )
        or incident.get(
            "analysis_risk_level"
        )
    )

    risk_score = (
        latest_analysis.get(
            "risk_score"
        )
    )

    category = (
        incident.get(
            "analysis_category"
        )
    )

    summary = (
        incident.get(
            "analysis_summary"
        )
        or ""
    )

    # ---------------------------------------------------------
    # Build frontend risk context
    # ---------------------------------------------------------

    parts: list[str] = []

    if risk_level:
        parts.append(
            f"Risk level: {risk_level}"
        )

    if risk_score is not None:
        parts.append(
            f"Risk score: {risk_score}"
        )

    if category:
        parts.append(
            f"Category: {category}"
        )

    if summary:
        parts.append(
            f"Summary: {summary}"
        )

    # ---------------------------------------------------------
    # Suggested actions
    # ---------------------------------------------------------

    suggested_actions = (
        context.get(
            "recommended_actions"
        )
        or []
    )

    if isinstance(
        suggested_actions,
        str,
    ):
        suggested_actions = [
            suggested_actions
        ]

    suggested_actions = [
        str(item)
        for item in suggested_actions
        if item
    ]

    return (
        "\n".join(parts)
        if parts
        else None,
        suggested_actions,
    )
