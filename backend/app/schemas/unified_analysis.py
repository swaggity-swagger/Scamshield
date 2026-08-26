from typing import Any, Literal

from pydantic import BaseModel, Field


class UnifiedEvidence(BaseModel):
    title: str
    description: str
    severity: str | None = None
    source: str | None = None


class UnifiedThreatFinding(BaseModel):
    indicator: str
    indicator_type: str
    source: str
    verdict: str | None = None
    confidence: float | None = None
    summary: str | None = None


class UnifiedAnalysisResponse(BaseModel):
    status: Literal[
        "completed",
        "partial",
        "failed",
    ]

    incident_id: int

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    risk_level: str

    confidence: int = Field(
        ge=0,
        le=100,
    )

    detected_language: str | None = None

    scam_categories: list[str] = []

    summary: str

    evidence: list[UnifiedEvidence] = []

    recommended_actions: list[str] = []

    safe_to_interact: bool

    source_type: str

    extracted_text: str | None = None

    urls: list[str] = []

    qr_data: list[str] = []

    upi_ids: list[str] = []

    threat_findings: list[UnifiedThreatFinding] = []

    warnings: list[str] = []

    raw_metadata: dict[str, Any] = {}