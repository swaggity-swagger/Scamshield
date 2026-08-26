from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User

from app.schemas.analysis import (
    AnalysisResultResponse,
)

from app.services.analysis_service import (
    save_analysis,
    get_analysis,
)

from app.services.incident_service import (
    get_user_incident,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Analysis"],
)


@router.post(
    "/{incident_id}/analysis",
    response_model=AnalysisResultResponse,
)
def ingest_analysis(
    incident_id: int,
    analysis_type: str,
    result: dict,
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

    return save_analysis(
        db=db,
        incident_id=incident_id,
        analysis_type=analysis_type,
        result=result,
    )


@router.get(
    "/{incident_id}/analysis",
)
def read_analysis(
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

    return get_analysis(
        db,
        incident_id,
    )