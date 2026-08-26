from pydantic import BaseModel, Field


class ThreatLookupRequest(BaseModel):
    indicator: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )

    indicator_type: str = Field(
        ...,
        pattern="^(url|domain|ip|hash)$",
    )