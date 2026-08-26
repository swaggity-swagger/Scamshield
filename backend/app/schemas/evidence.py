from datetime import datetime

from pydantic import BaseModel, Field


class EvidenceCreate(BaseModel):
    evidence_type: str = Field(
        ...,
        max_length=50,
    )

    title: str = Field(
        ...,
        max_length=255,
    )

    description: str

    severity: str | None = Field(
        default=None,
        max_length=20,
    )

    source: str | None = Field(
        default=None,
        max_length=100,
    )


class EvidenceResponse(BaseModel):
    id: int
    incident_id: int
    evidence_type: str
    title: str
    description: str
    severity: str | None
    source: str | None
    filename: str | None
    stored_path: str | None
    sha256: str | None
    created_at: datetime

    class Config:
        from_attributes = True