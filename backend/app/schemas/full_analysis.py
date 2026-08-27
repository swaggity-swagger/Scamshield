"""Pydantic models for the unified /analysis/full endpoint.

The original endpoints return a flat JSON with fields like ``risk_score``,
``risk_level`` and ``evidence``. To keep the existing frontend code working
without major rewrites we expose those same fields at the top level, while
also providing the richer ``nlp_result`` and ``cyber_result`` objects.
"""

from __future__ import annotations

from typing import Any, Literal, List

from pydantic import BaseModel, Field


class FullAnalysisResponse(BaseModel):
    """Combined result of NLP and cybersecurity analysis.

    Compatibility fields (mirroring the old ``analysis_service`` output) are
    populated from the NLP analyser – they allow the current UI to continue
    displaying the same information. Additional fields expose the full raw
    results for any future extensions.
    """

    # Compatibility fields (from member3/NLP)
    risk_score: int = Field(..., description="Risk score from the NLP analyser.")
    risk_level: Literal["low", "medium", "high", "critical", "unknown"] = Field(
        ..., description="Risk level from the NLP analyser.")
    confidence: float = Field(..., description="Confidence (0‑1) from the NLP analyser.")
    detected_language: Literal["en", "hi", "mr", "mixed"] = Field(
        ..., description="Detected language of the input text.")
    scam_categories: List[str] = Field(..., description="Scam categories identified.")
    summary: str = Field(..., description="Human‑readable summary/explanation.")
    evidence: List[Any] = Field(..., description="List of evidence objects from NLP.")
    recommended_actions: List[str] = Field(..., description="Suggested user actions.")

    # Full raw results – optional for downstream consumers
    nlp_result: dict = Field(..., description="Complete NLP result object.")
    cyber_result: dict = Field(..., description="Complete cybersecurity result object.")

    # Aggregated fields across both analyses
    combined_risk_score: int = Field(..., description="Maximum risk score from both analyses.")
    combined_risk_level: Literal["low", "medium", "high", "critical", "unknown"] = Field(
        ..., description="Highest risk level across both analyses.")
    recommended_actions: List[str] = Field(
        ..., description="Deduped actions from both engines.")
