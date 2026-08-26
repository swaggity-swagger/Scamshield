from datetime import datetime

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
from app.models.incident import Incident
from app.models.user import User
from app.schemas.incident_status import (
    IncidentStatusUpdate,
)
from app.schemas.incident_summary import (
    IncidentSummaryResponse,
)
from app.schemas.timeline import (
    TimelineCreate,
)
from app.services.incident_service import (
    get_user_incident,
)
from app.services.incident_summary_service import (
    get_incident_summary,
)
from app.services.timeline_service import (
    create_timeline_event,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


# ============================================================
# CREATE INCIDENT
# ============================================================

@router.post("")
def create_incident(
    incident_type: str,
    amount: float | None = None,
    transaction_id: str | None = None,
    payment_method: str | None = None,
    description: str | None = None,
    incident_date: str | None = None,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Create a new incident for the authenticated user.
    """

    parsed_incident_date = None

    if incident_date:
        try:
            parsed_incident_date = (
                datetime.fromisoformat(
                    incident_date
                )
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "incident_date must be a valid "
                    "ISO-8601 datetime."
                ),
            ) from exc

    incident = Incident(
        user_id=current_user.id,
        incident_type=incident_type,
        amount=amount,
        transaction_id=transaction_id,
        payment_method=payment_method,
        description=description,
        incident_date=parsed_incident_date,
        status="draft",
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


# ============================================================
# LIST USER INCIDENTS
# ============================================================

@router.get("")
def get_incidents(
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Return incidents belonging only to the
    authenticated user.
    """

    statement = (
        select(Incident)
        .where(
            Incident.user_id
            == current_user.id
        )
        .order_by(
            Incident.created_at.desc()
        )
    )

    return list(
        db.scalars(statement).all()
    )


# ============================================================
# GET SINGLE INCIDENT
# ============================================================

@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Return one incident owned by the
    authenticated user.
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

    return incident


# ============================================================
# INCIDENT SUMMARY
# ============================================================

@router.get(
    "/{incident_id}/summary",
    response_model=IncidentSummaryResponse,
)
def incident_summary(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Return one frontend-ready summary containing:

        Incident
        Latest analysis
        Evidence
        Threat findings
        Timeline
        Report
        Recommended actions
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

    summary = get_incident_summary(
        db=db,
        incident_id=incident_id,
    )

    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident summary not found.",
        )

    return summary


# ============================================================
# INCIDENT STATUS
# ============================================================

@router.patch(
    "/{incident_id}/status",
)
def update_incident_status(
    incident_id: int,
    data: IncidentStatusUpdate,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Update the lifecycle status of an incident
    and record the change in the timeline.
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

    old_status = incident.status

    if old_status == data.status:
        return incident

    incident.status = data.status

    db.commit()
    db.refresh(incident)

    create_timeline_event(
        db=db,
        incident_id=incident.id,
        data=TimelineCreate(
            event_time=datetime.utcnow(),
            event_type="STATUS_CHANGED",
            description=(
                f"Incident status changed "
                f"from {old_status} to "
                f"{data.status}."
            ),
        ),
    )

    db.refresh(incident)

    return incident