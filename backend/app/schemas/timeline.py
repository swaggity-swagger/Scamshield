from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TimelineCreate(BaseModel):
    event_time: datetime
    event_type: str = Field(
        min_length=2,
        max_length=100,
    )
    description: str = Field(
        min_length=1,
        max_length=2000,
    )


class TimelineResponse(BaseModel):
    id: int
    incident_id: int
    event_time: datetime
    event_type: str
    description: str
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )