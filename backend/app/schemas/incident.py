from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IncidentCreate(BaseModel):
    incident_type: str = Field(
        min_length=2,
        max_length=100,
    )

    amount: float | None = Field(
        default=None,
        ge=0,
    )

    transaction_id: str | None = Field(
        default=None,
        max_length=255,
    )

    payment_method: str | None = Field(
        default=None,
        max_length=100,
    )

    description: str | None = None

    incident_date: datetime | None = None


class IncidentUpdate(BaseModel):
    incident_type: str | None = Field(
        default=None,
        min_length=2,
        max_length=100,
    )

    amount: float | None = Field(
        default=None,
        ge=0,
    )

    transaction_id: str | None = Field(
        default=None,
        max_length=255,
    )

    payment_method: str | None = Field(
        default=None,
        max_length=100,
    )

    description: str | None = None

    incident_date: datetime | None = None

    status: str | None = Field(
        default=None,
        max_length=50,
    )

    analysis_category: str | None = Field(
        default=None,
        max_length=100,
    )

    analysis_risk_level: str | None = Field(
        default=None,
        max_length=50,
    )

    analysis_summary: str | None = None


class IncidentResponse(BaseModel):
    id: int
    user_id: int
    incident_type: str
    amount: float | None
    transaction_id: str | None
    payment_method: str | None
    description: str | None
    incident_date: datetime | None

    status: str
    analysis_category: str | None
    analysis_risk_level: str | None
    analysis_summary: str | None

    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )