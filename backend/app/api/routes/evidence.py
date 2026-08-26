from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User

from app.schemas.evidence import (
    EvidenceCreate,
    EvidenceResponse,
)

from app.services.evidence_service import (
    save_evidence,
    get_evidence,
)

from app.services.incident_service import (
    get_user_incident,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Evidence"],
)


@router.post(
    "/{incident_id}/evidence",
    response_model=EvidenceResponse,
)
def add_evidence(
    incident_id: int,
    data: EvidenceCreate,
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

    return save_evidence(
        db=db,
        incident_id=incident_id,
        evidence_type=data.evidence_type,
        title=data.title,
        description=data.description,
        severity=data.severity,
        source=data.source,
    )


@router.get(
    "/{incident_id}/evidence",
    response_model=list[EvidenceResponse],
)
def list_evidence(
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

    return get_evidence(
        db,
        incident_id,
    )