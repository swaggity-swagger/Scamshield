from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.timeline import Timeline
from app.schemas.timeline import TimelineCreate


def create_timeline_event(
    db: Session,
    incident_id: int,
    data: TimelineCreate,
) -> Timeline:
    event = Timeline(
        incident_id=incident_id,
        event_time=data.event_time,
        event_type=data.event_type,
        description=data.description,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


def get_timeline(
    db: Session,
    incident_id: int,
) -> list[Timeline]:
    statement = (
        select(Timeline)
        .where(
            Timeline.incident_id == incident_id
        )
        .order_by(
            Timeline.event_time.asc()
        )
    )

    return list(db.scalars(statement).all())