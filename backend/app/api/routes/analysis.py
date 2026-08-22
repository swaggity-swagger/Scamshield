from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.analysis import TextAnalysisResponse
from app.services.analysis_service import analyze_message


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"]
)


class TextAnalysisRequest(BaseModel):
    message: str


@router.post("/text", response_model=TextAnalysisResponse)
def analyze_text(data: TextAnalysisRequest):
    return analyze_message(data.message)