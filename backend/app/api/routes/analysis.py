from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User

from app.schemas.analysis import (
    AnalysisResultCreate,
    AnalysisResultResponse,
)

from app.schemas.unified_analysis import (
    UnifiedAnalysisResponse,
)

from app.schemas.analyze import (
    UnifiedAnalyzeRequest,
)

from app.services.analysis_service import (
    get_analysis,
    save_analysis,
)

from app.services.incident_service import (
    get_user_incident,
)

from app.services.orchestration_service import (
    run_image_analysis,
    run_qr_analysis,
    run_text_analysis,
    run_url_analysis,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Analysis"],
)


# ============================================================
# MANUAL ANALYSIS STORAGE
# ============================================================

@router.post(
    "/{incident_id}/analysis",
    response_model=AnalysisResultResponse,
)
def create_analysis(
    incident_id: int,
    data: AnalysisResultCreate,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Store an already-computed analysis result
    for an incident.
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    result = {
        "risk_score": data.risk_score,
        "risk_level": data.risk_level,
        "confidence": data.confidence,
    }

    if data.result_json:
        result.update(
            data.result_json
        )

    return save_analysis(
        db=db,
        incident_id=incident_id,
        analysis_type=data.analysis_type,
        result=result,
    )


# ============================================================
# ANALYSIS HISTORY
# ============================================================

@router.get(
    "/{incident_id}/analysis",
    response_model=list[AnalysisResultResponse],
)
def list_analysis(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Return analysis history for an incident.
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    return get_analysis(
        db=db,
        incident_id=incident_id,
    )


# ============================================================
# TEXT ANALYSIS
# ============================================================

@router.post(
    "/{incident_id}/analyze-text",
    response_model=UnifiedAnalysisResponse,
)
async def analyze_incident_text(
    incident_id: int,
    text: str,
    preferred_language: str = "en",
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Run the complete text-analysis pipeline.

    Pipeline:
        Text
        -> NLP
        -> Cybersecurity
        -> Threat Intelligence
        -> AnalysisResult
        -> Evidence
        -> ThreatFinding
        -> Incident update
        -> Timeline
        -> Report
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    if not text or not text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text cannot be empty.",
        )

    preferred_language = (
        preferred_language
        .strip()
        .lower()
    )

    if preferred_language not in {
        "en",
        "hi",
        "mr",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "preferred_language must be "
                "'en', 'hi', or 'mr'."
            ),
        )

    return await run_text_analysis(
        db=db,
        incident=incident,
        text=text.strip(),
        preferred_language=preferred_language,
    )


# ============================================================
# URL ANALYSIS
# ============================================================

@router.post(
    "/{incident_id}/analyze-url",
    response_model=UnifiedAnalysisResponse,
)
async def analyze_incident_url(
    incident_id: int,
    url: str,
    preferred_language: str = "en",
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Run the complete URL-analysis pipeline.

    Pipeline:
        URL
        -> URL analyzer
        -> Cybersecurity
        -> Threat Intelligence
        -> AnalysisResult
        -> Evidence
        -> ThreatFinding
        -> Incident update
        -> Timeline
        -> Report
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    if not url or not url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty.",
        )

    preferred_language = (
        preferred_language
        .strip()
        .lower()
    )

    if preferred_language not in {
        "en",
        "hi",
        "mr",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "preferred_language must be "
                "'en', 'hi', or 'mr'."
            ),
        )

    return await run_url_analysis(
        db=db,
        incident=incident,
        url=url.strip(),
        preferred_language=preferred_language,
    )


# ============================================================
# IMAGE / SCREENSHOT ANALYSIS
# ============================================================

@router.post(
    "/{incident_id}/analyze-image",
    response_model=UnifiedAnalysisResponse,
)
async def analyze_incident_image(
    incident_id: int,
    file: UploadFile = File(...),
    preferred_language: str = "en",
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Analyze a screenshot/image using:

        OCR
        QR decoding
        NLP
        Cybersecurity
        Threat Intelligence
        Database persistence
        Timeline
        Report
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    preferred_language = (
        preferred_language
        .strip()
        .lower()
    )

    if preferred_language not in {
        "en",
        "hi",
        "mr",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "preferred_language must be "
                "'en', 'hi', or 'mr'."
            ),
        )

    allowed_types = {
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/webp",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported image type.",
        )

    image_bytes = await file.read()

    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded image is empty.",
        )

    max_size = 10 * 1024 * 1024

    if len(image_bytes) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Image must be 10 MB or smaller.",
        )

    return await run_image_analysis(
        db=db,
        incident=incident,
        image_bytes=image_bytes,
        preferred_language=preferred_language,
    )


# ============================================================
# QR ANALYSIS
# ============================================================

@router.post(
    "/{incident_id}/analyze-qr",
    response_model=UnifiedAnalysisResponse,
)
async def analyze_incident_qr(
    incident_id: int,
    file: UploadFile = File(...),
    preferred_language: str = "en",
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Decode and analyze a dedicated QR-code image.
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    preferred_language = (
        preferred_language
        .strip()
        .lower()
    )

    if preferred_language not in {
        "en",
        "hi",
        "mr",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "preferred_language must be "
                "'en', 'hi', or 'mr'."
            ),
        )

    allowed_types = {
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/webp",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported image type.",
        )

    image_bytes = await file.read()

    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded image is empty.",
        )

    max_size = 10 * 1024 * 1024

    if len(image_bytes) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Image must be 10 MB or smaller.",
        )

    try:
        return await run_qr_analysis(
            db=db,
            incident=incident,
            image_bytes=image_bytes,
            preferred_language=preferred_language,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ============================================================
# UNIFIED TEXT / URL ANALYSIS
# ============================================================

@router.post(
    "/{incident_id}/analyze",
    response_model=UnifiedAnalysisResponse,
)
async def analyze_incident(
    incident_id: int,
    data: UnifiedAnalyzeRequest,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Unified text/URL analysis endpoint.

    The frontend can use one endpoint for both
    text and URL submissions.
    """

    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    value = data.value.strip()

    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Input cannot be empty.",
        )

    if data.input_type == "text":
        return await run_text_analysis(
            db=db,
            incident=incident,
            text=value,
            preferred_language=(
                data.preferred_language
            ),
        )

    if data.input_type == "url":
        return await run_url_analysis(
            db=db,
            incident=incident,
            url=value,
            preferred_language=(
                data.preferred_language
            ),
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unsupported input type.",
    )
    