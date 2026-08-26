import hashlib
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
)
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.services.evidence_service import save_evidence
from app.services.incident_service import get_user_incident


router = APIRouter(
    prefix="/incidents",
    tags=["Evidence Upload"],
)


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
}


@router.post(
    "/{incident_id}/evidence-file"
)
async def upload_evidence(
    incident_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    incident = get_user_incident(
        db,
        incident_id,
        current_user.id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    original_name = file.filename or "uploaded_file"

    extension = Path(
        original_name
    ).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Only image files are allowed.",
        )

    content = await file.read()

    if len(content) > MAX_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum is 5 MB.",
        )

    sha256 = hashlib.sha256(
        content
    ).hexdigest()

    stored_name = (
        f"{sha256}{extension}"
    )

    destination = (
        UPLOAD_DIR / stored_name
    )

    destination.write_bytes(content)

    evidence = save_evidence(
        db=db,
        incident_id=incident_id,
        evidence_type="uploaded_image",
        title="Uploaded screenshot or QR image",
        description=(
            "Image uploaded for scam analysis."
        ),
        severity=None,
        source="user_upload",
        filename=original_name,
        stored_path=str(destination),
        sha256=sha256,
    )

    return {
        "message": "Evidence uploaded.",
        "evidence_id": evidence.id,
        "filename": original_name,
        "sha256": sha256,
        "path": str(destination),
    }