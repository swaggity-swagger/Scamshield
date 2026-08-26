from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AnalysisResultCreate(BaseModel):
    analysis_type: str = Field(
        ...,
        max_length=50,
    )

    risk_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    risk_level: str | None = Field(
        default=None,
        max_length=20,
    )

    confidence: float | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    result_json: dict[str, Any] | None = None


class AnalysisResultResponse(BaseModel):
    id: int
    incident_id: int
    analysis_type: str
    risk_score: float | None
    risk_level: str | None
    confidence: float | None
    result_json: dict[str, Any] | None
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )