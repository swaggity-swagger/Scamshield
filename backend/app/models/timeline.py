from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class Timeline(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey(
            "incidents.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    event_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )