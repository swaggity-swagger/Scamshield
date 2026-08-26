from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.schemas.timeline import (
    TimelineCreate,
    TimelineResponse,
)
from app.services.incident_service import get_incident
from app.services.timeline_service import (
    create_timeline_event,
    get_timeline,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Timeline"],
)


@router.post(
    "/{incident_id}/timeline",
    response_model=TimelineResponse,
)
def add_timeline_event(
    incident_id: int,
    data: TimelineCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = get_incident(
        db=db,
        incident_id=incident_id,
        user_id=current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return create_timeline_event(
        db=db,
        incident_id=incident_id,
        data=data,
    )


@router.get(
    "/{incident_id}/timeline",
    response_model=list[TimelineResponse],
)
def list_timeline(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = get_incident(
        db=db,
        incident_id=incident_id,
        user_id=current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return get_timeline(
        db=db,
        incident_id=incident_id,
    )