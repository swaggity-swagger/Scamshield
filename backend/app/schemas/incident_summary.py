from typing import Any

from pydantic import BaseModel


class IncidentSummaryResponse(BaseModel):
    incident: dict[str, Any]
    analysis: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] = []
    threat_findings: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    report: dict[str, Any] | None = None
    recommended_actions: list[str] = []