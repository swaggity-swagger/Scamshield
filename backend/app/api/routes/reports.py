from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.services.incident_service import (
    get_user_incident,
)
from app.services.report_service import (
    build_incident_summary,
    create_or_update_report,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Reports"],
)


@router.get(
    "/{incident_id}/summary"
)
def incident_summary(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return build_incident_summary(
        db,
        incident_id,
    )


@router.post(
    "/{incident_id}/report"
)
def generate_report(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    report = create_or_update_report(
        db,
        incident_id,
    )

    return {
        "report_id": report.id,
        "summary": report.summary,
        "recommendation": report.recommendation,
        "report_data": report.report_data,
    }


@router.get(
    "/{incident_id}/report"
)
def read_report(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    from sqlalchemy import select
    from app.models.report import Report

    report = db.scalar(
        select(Report).where(
            Report.incident_id
            == incident_id
        )
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Report not generated yet.",
        )

    return {
        "report_id": report.id,
        "summary": report.summary,
        "recommendation": report.recommendation,
        "report_data": report.report_data,
    }