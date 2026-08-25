from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeTextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10000, description="Message or OCR-extracted text")
    preferred_language: Literal["en", "hi", "mr"] = "en"


class Evidence(BaseModel):
    signal: str
    matched_text: str
    severity: Literal["low", "medium", "high", "critical"]
    score_impact: int
    explanation: str


class AnalyzeTextResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high", "critical"]
    confidence: int = Field(ge=0, le=100)
    detected_language: Literal["en", "hi", "mr", "mixed"]
    scam_categories: list[str]
    summary: str
    evidence: list[Evidence]
    recommended_actions: list[str]
    safe_to_interact: bool
