from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.incident import Incident
from app.models.user import User


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


@router.post("")
def create_incident(
    incident_type: str,
    amount: float | None = None,
    transaction_id: str | None = None,
    payment_method: str | None = None,
    description: str | None = None,
    incident_date: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident = Incident(
        user_id=current_user.id,
        incident_type=incident_type,
        amount=amount,
        transaction_id=transaction_id,
        payment_method=payment_method,
        description=description,
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


@router.get("")
def get_incidents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incidents = (
        db.query(Incident)
        .filter(
            Incident.user_id == current_user.id
        )
        .order_by(
            Incident.created_at.desc()
        )
        .all()
    )

    return incidents


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id,
            Incident.user_id == current_user.id,
        )
        .first()
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    return incident