from typing import Literal, Optional

from pydantic import BaseModel


# -----------------------------
# TEXT ANALYSIS
# -----------------------------

class TextAnalysisRequest(BaseModel):
    message: str
    language: Literal["en", "hi", "mr"] = "en"


class TextAnalysisResponse(BaseModel):
    language: str
    risk_level: str
    category: str
    confidence: Optional[float] = None
    indicators: list[str]
    explanation: str
    recommended_actions: list[str]


# -----------------------------
# URL ANALYSIS
# -----------------------------

class URLAnalysisRequest(BaseModel):
    url: str
    language: Literal["en", "hi", "mr"] = "en"


class URLFeatures(BaseModel):
    scheme: str
    domain: str
    uses_https: bool
    uses_ip_address: bool
    has_at_symbol: bool
    is_long_url: bool
    has_many_subdomains: bool
    is_punycode: bool
    is_shortened_url: bool
    suspicious_keywords: list[str]


class URLAnalysisResponse(BaseModel):
    url: str
    language: str
    risk_level: str
    category: str
    confidence: Optional[float] = None
    indicators: list[str]
    features: URLFeatures
    explanation: str
    recommended_actions: list[str]