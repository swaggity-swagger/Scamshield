from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.analysis import (
    TextAnalysisRequest,
    TextAnalysisResponse,
    URLAnalysisRequest,
    URLAnalysisResponse,
)
from app.services.analysis_service import analyze_message
from app.services.url_service import analyze_url


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)


@router.post("/text", response_model=TextAnalysisResponse)
def analyze_text(data: TextAnalysisRequest):
    return analyze_message(
        data.message,
        data.language,
    )


@router.post("/url", response_model=URLAnalysisResponse)
def analyze_url_endpoint(data: URLAnalysisRequest):
    return analyze_url(
        data.url,
    )