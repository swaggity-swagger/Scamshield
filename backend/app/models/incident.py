from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    incident_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    amount: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    transaction_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    payment_method: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    incident_date: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    # Incident lifecycle.
    # draft -> in_progress -> completed/partial -> reported -> closed
    status: Mapped[str] = mapped_column(
        String(50),
        default="draft",
        nullable=False,
        index=True,
    )

    # Latest high-level result from ScamShield analysis.
    analysis_category: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    analysis_risk_level: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    analysis_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )