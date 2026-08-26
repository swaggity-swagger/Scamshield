from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ReportCreate(BaseModel):
    summary: str
    recommendation: str
    report_data: dict[str, Any] | None = None


class ReportResponse(BaseModel):
    id: int
    incident_id: int
    summary: str
    recommendation: str
    report_data: dict[str, Any] | None
    created_at: datetime

    class Config:
        from_attributes = True