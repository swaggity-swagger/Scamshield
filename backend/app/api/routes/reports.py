from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.report import Report
from app.models.user import User
from app.services.incident_service import (
    get_user_incident,
)
from app.services.report_service import (
    create_or_update_report,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Reports"],
)


# ============================================================
# GENERATE / REFRESH REPORT
# ============================================================

@router.post(
    "/{incident_id}/report",
)
def generate_report(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(
        get_db
    ),
):
    """
    Generate or refresh the report for an incident.
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    report = create_or_update_report(
        db=db,
        incident_id=incident_id,
    )

    return {
        "report_id": report.id,
        "incident_id": report.incident_id,
        "summary": report.summary,
        "recommendation": report.recommendation,
        "report_data": report.report_data,
    }


# ============================================================
# READ REPORT
# ============================================================

@router.get(
    "/{incident_id}/report",
)
def read_report(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(
        get_db
    ),
):
    """
    Return the existing report for an incident.
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    report = db.scalar(
        select(Report).where(
            Report.incident_id
            == incident_id
        )
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not generated yet.",
        )

    return {
        "report_id": report.id,
        "incident_id": report.incident_id,
        "summary": report.summary,
        "recommendation": report.recommendation,
        "report_data": report.report_data,
    }