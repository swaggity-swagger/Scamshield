from typing import Any

from pydantic import BaseModel


class DashboardSummaryResponse(BaseModel):
    total_incidents: int
    open_incidents: int
    high_risk_incidents: int
    critical_incidents: int
    recent_incidents: list[dict[str, Any]]