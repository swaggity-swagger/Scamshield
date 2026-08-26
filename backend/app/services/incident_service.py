from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
)


def create_incident(
    db: Session,
    user_id: int,
    data: IncidentCreate,
) -> Incident:
    """
    Create a new incident for the authenticated user.
    """

    incident = Incident(
        user_id=user_id,
        incident_type=data.incident_type,
        amount=data.amount,
        transaction_id=data.transaction_id,
        payment_method=data.payment_method,
        description=data.description,
        incident_date=data.incident_date,
        status="draft",
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


def get_user_incidents(
    db: Session,
    user_id: int,
) -> list[Incident]:
    """
    Return all incidents belonging to the specified user.
    """

    statement = (
        select(Incident)
        .where(
            Incident.user_id == user_id
        )
        .order_by(
            Incident.created_at.desc()
        )
    )

    return list(
        db.scalars(statement).all()
    )


def get_incident(
    db: Session,
    incident_id: int,
    user_id: int,
) -> Incident | None:
    """
    Return an incident only if it belongs to the specified user.
    """

    statement = select(Incident).where(
        Incident.id == incident_id,
        Incident.user_id == user_id,
    )

    return db.scalar(statement)


def get_user_incident(
    db: Session,
    incident_id: int,
    user_id: int,
) -> Incident | None:
    """
    Backward-compatible helper used by existing analysis routes.

    This keeps the existing get_user_incident() contract while
    using the same ownership-safe lookup as get_incident().
    """

    return get_incident(
        db=db,
        incident_id=incident_id,
        user_id=user_id,
    )


def update_incident(
    db: Session,
    incident: Incident,
    data: IncidentUpdate,
) -> Incident:
    """
    Update an existing incident.
    """

    values = data.model_dump(
        exclude_unset=True
    )

    for field, value in values.items():
        setattr(
            incident,
            field,
            value,
        )

    db.commit()
    db.refresh(incident)

    return incident