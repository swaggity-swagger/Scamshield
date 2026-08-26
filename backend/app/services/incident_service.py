from sqlalchemy import select

from app.models.incident import Incident


def get_user_incident(
    db,
    incident_id: int,
    user_id: int,
):
    statement = select(Incident).where(
        Incident.id == incident_id,
        Incident.user_id == user_id,
    )

    return db.scalar(statement)