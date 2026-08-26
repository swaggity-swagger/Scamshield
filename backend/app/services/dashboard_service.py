from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.incident import Incident


def get_dashboard_summary(
    db: Session,
    user_id: int,
) -> dict:

    total = db.scalar(
        select(
            func.count(Incident.id)
        ).where(
            Incident.user_id == user_id
        )
    ) or 0

    open_count = db.scalar(
        select(
            func.count(Incident.id)
        ).where(
            Incident.user_id == user_id,
            Incident.status != "closed",
        )
    ) or 0

    high_risk = db.scalar(
        select(
            func.count(Incident.id)
        ).where(
            Incident.user_id == user_id,
            Incident.analysis_risk_level == "high",
        )
    ) or 0

    critical = db.scalar(
        select(
            func.count(Incident.id)
        ).where(
            Incident.user_id == user_id,
            Incident.analysis_risk_level == "critical",
        )
    ) or 0

    recent = db.scalars(
        select(Incident)
        .where(
            Incident.user_id == user_id
        )
        .order_by(
            Incident.created_at.desc()
        )
        .limit(10)
    ).all()

    return {
        "total_incidents": total,
        "open_incidents": open_count,
        "high_risk_incidents": high_risk,
        "critical_incidents": critical,
        "recent_incidents": [
            {
                "id": item.id,
                "incident_type": item.incident_type,
                "status": item.status,
                "risk_level": item.analysis_risk_level,
                "category": item.analysis_category,
                "summary": item.analysis_summary,
                "created_at": item.created_at,
            }
            for item in recent
        ],
    }