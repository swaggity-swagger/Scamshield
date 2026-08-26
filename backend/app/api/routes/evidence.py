from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.schemas.evidence import (
    EvidenceCreate,
    EvidenceResponse,
)
from app.services.evidence_service import (
    delete_evidence,
    get_evidence,
    get_evidence_item,
    save_evidence,
    save_uploaded_evidence,
)
from app.services.incident_service import (
    get_user_incident,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Evidence"],
)


# ============================================================
# ADD EVIDENCE METADATA
# ============================================================

@router.post(
    "/{incident_id}/evidence",
    response_model=EvidenceResponse,
)
def add_evidence(
    incident_id: int,
    data: EvidenceCreate,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(
        get_db
    ),
):
    """
    Create an evidence record without uploading a file.
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

    return save_evidence(
        db=db,
        incident_id=incident_id,
        evidence_type=data.evidence_type,
        title=data.title,
        description=data.description,
        severity=data.severity,
        source=data.source,
    )


# ============================================================
# UPLOAD EVIDENCE FILE
# ============================================================

@router.post(
    "/{incident_id}/evidence/upload",
    response_model=EvidenceResponse,
)
async def upload_evidence(
    incident_id: int,
    file: UploadFile = File(...),
    evidence_type: str = Query(
        default="file",
        max_length=100,
    ),
    title: str | None = Query(
        default=None,
        max_length=255,
    ),
    description: str | None = Query(
        default=None,
        max_length=2000,
    ),
    severity: str | None = Query(
        default=None,
        max_length=50,
    ),
    source: str = Query(
        default="user_upload",
        max_length=100,
    ),
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(
        get_db
    ),
):
    """
    Upload a file as evidence for an incident.

    The file is stored on disk.
    PostgreSQL stores filename, path and SHA-256.
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

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required.",
        )

    max_size = 20 * 1024 * 1024

    file_bytes = await file.read()

    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    if len(file_bytes) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Evidence file must be 20 MB or smaller.",
        )

    safe_content_type = (
        file.content_type
        or "application/octet-stream"
    )

    allowed_image_types = {
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/webp",
    }

    allowed_types = (
        allowed_image_types
        | {
            "application/pdf",
            "text/plain",
        }
    )

    if (
        safe_content_type
        not in allowed_types
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Unsupported evidence file type. "
                "Allowed types: PNG, JPEG, WEBP, PDF and TXT."
            ),
        )

    return save_uploaded_evidence(
        db=db,
        incident_id=incident_id,
        filename=file.filename,
        file_bytes=file_bytes,
        evidence_type=evidence_type,
        title=title,
        description=description,
        severity=severity,
        source=source,
    )


# ============================================================
# LIST EVIDENCE
# ============================================================

@router.get(
    "/{incident_id}/evidence",
    response_model=list[EvidenceResponse],
)
def list_evidence(
    incident_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(
        get_db
    ),
):
    """
    Return all evidence belonging to an incident.
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

    return get_evidence(
        db,
        incident_id,
    )


# ============================================================
# GET ONE EVIDENCE ITEM
# ============================================================

@router.get(
    "/{incident_id}/evidence/{evidence_id}",
    response_model=EvidenceResponse,
)
def get_one_evidence(
    incident_id: int,
    evidence_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(
        get_db
    ),
):
    """
    Return one evidence record belonging to the incident.
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

    evidence = get_evidence_item(
        db=db,
        evidence_id=evidence_id,
        incident_id=incident_id,
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found.",
        )

    return evidence


# ============================================================
# DELETE EVIDENCE
# ============================================================

@router.delete(
    "/{incident_id}/evidence/{evidence_id}",
)
def remove_evidence(
    incident_id: int,
    evidence_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(
        get_db
    ),
):
    """
    Delete an evidence record and its stored file.
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

    deleted = delete_evidence(
        db=db,
        evidence_id=evidence_id,
        incident_id=incident_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found.",
        )

    return {
        "message": "Evidence deleted."
    }