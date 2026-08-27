from typing import Literal

from pydantic import BaseModel


class AIEvidence(BaseModel):
    signal: str
    matched_text: str
    severity: Literal["low", "medium", "high", "critical"]
    score_impact: int
    explanation: str