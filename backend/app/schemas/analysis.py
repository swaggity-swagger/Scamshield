from pydantic import BaseModel
from typing import Optional


class TextAnalysisResponse(BaseModel):
    risk_level: str
    category: str
    confidence: Optional[float] = None
    indicators: list[str]
    explanation: str
    recommended_actions: list[str]