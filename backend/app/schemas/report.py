from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ReportResponse(BaseModel):
    id: int
    incident_id: int
    summary: str
    recommendation: str
    report_data: dict[str, Any] | None
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )