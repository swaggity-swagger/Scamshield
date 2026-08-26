from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.report import Report
from app.models.timeline import Timeline

from app.services.report_service import (
    build_incident_summary,
)


def get_incident_summary(
    db: Session,
    incident_id: int,
) -> dict[str, Any] | None:
    """
    Build the complete frontend-facing summary for
    one incident.

    The report service remains the single source of truth
    for analysis/evidence/threat aggregation.

    This service adds:
        - incident metadata
        - timeline
        - current report
        - frontend-friendly structure
    """

    # ---------------------------------------------------------
    # INCIDENT
    # ---------------------------------------------------------

    incident = db.scalar(
        select(Incident)
        .where(
            Incident.id == incident_id
        )
    )

    if incident is None:
        return None

    # ---------------------------------------------------------
    # CORE ANALYSIS SUMMARY
    # ---------------------------------------------------------

    core_summary = (
        build_incident_summary(
            db=db,
            incident_id=incident_id,
        )
    )

    # ---------------------------------------------------------
    # TIMELINE
    # ---------------------------------------------------------

    timeline_items = db.scalars(
        select(Timeline)
        .where(
            Timeline.incident_id
            == incident_id
        )
        .order_by(
            Timeline.event_time.desc()
        )
    ).all()

    # ---------------------------------------------------------
    # REPORT
    # ---------------------------------------------------------

    report = db.scalar(
        select(Report)
        .where(
            Report.incident_id
            == incident_id
        )
    )

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    recommended_actions = (
        core_summary.get(
            "recommendations"
        )
        or []
    )

    if isinstance(
        recommended_actions,
        str,
    ):
        recommended_actions = [
            recommended_actions
        ]

    # ---------------------------------------------------------
    # LATEST ANALYSIS
    # ---------------------------------------------------------

    analyses = (
        core_summary.get(
            "analyses"
        )
        or []
    )

    latest_analysis = (
        analyses[0]
        if analyses
        else None
    )

    # ---------------------------------------------------------
    # FRONTEND SUMMARY
    # ---------------------------------------------------------

    return {
        "incident": {
            "id": incident.id,
            "user_id": incident.user_id,
            "incident_type": (
                incident.incident_type
            ),
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
                incident.incident_date
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
                incident.created_at
            ),
            "updated_at": (
                incident.updated_at
            ),
        },

        "analysis": (
            {
                "id": latest_analysis.get(
                    "id"
                ),
                "type": latest_analysis.get(
                    "type"
                ),
                "risk_score": latest_analysis.get(
                    "risk_score"
                ),
                "risk_level": latest_analysis.get(
                    "risk_level"
                ),
                "confidence": latest_analysis.get(
                    "confidence"
                ),
                "result": latest_analysis.get(
                    "result"
                ),
            }
            if latest_analysis
            else None
        ),

        "evidence": (
            core_summary.get(
                "evidence"
            )
            or []
        ),

        "threat_findings": (
            core_summary.get(
                "threat_findings"
            )
            or []
        ),

        "timeline": [
            {
                "id": item.id,
                "event_time": (
                    item.event_time
                ),
                "event_type": (
                    item.event_type
                ),
                "description": (
                    item.description
                ),
            }
            for item in timeline_items
        ],

        "report": (
            {
                "id": report.id,
                "summary": report.summary,
                "recommendation": (
                    report.recommendation
                ),
                "report_data": (
                    report.report_data
                ),
            }
            if report
            else None
        ),

        "recommended_actions": (
            recommended_actions
        ),
    }