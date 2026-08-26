from typing import Literal

from pydantic import BaseModel


class IncidentStatusUpdate(BaseModel):
    status: Literal[
        "draft",
        "in_progress",
        "completed",
        "partial",
        "reported",
        "closed",
    ]