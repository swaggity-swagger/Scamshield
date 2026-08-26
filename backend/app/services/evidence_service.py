from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence import Evidence


# ============================================================
# FILE STORAGE
# ============================================================

EVIDENCE_STORAGE_DIR = (
    Path(__file__).resolve().parents[2]
    / "storage"
    / "evidence"
)


def save_evidence(
    db: Session,
    incident_id: int,
    evidence_type: str,
    title: str,
    description: str,
    severity: str | None,
    source: str | None,
    filename: str | None = None,
    stored_path: str | None = None,
    sha256: str | None = None,
) -> Evidence:
    """
    Save evidence metadata for an incident.
    """

    evidence = Evidence(
        incident_id=incident_id,
        evidence_type=evidence_type,
        title=title,
        description=description,
        severity=severity,
        source=source,
        filename=filename,
        stored_path=stored_path,
        sha256=sha256,
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    return evidence


def save_uploaded_evidence(
    db: Session,
    incident_id: int,
    filename: str,
    file_bytes: bytes,
    evidence_type: str = "file",
    title: str | None = None,
    description: str | None = None,
    severity: str | None = None,
    source: str | None = "user_upload",
) -> Evidence:
    """
    Store an uploaded evidence file on disk and create
    the corresponding Evidence database record.

    The file itself is stored outside PostgreSQL.
    PostgreSQL stores only metadata and SHA-256.
    """

    if not file_bytes:
        raise ValueError(
            "Uploaded file is empty."
        )

    EVIDENCE_STORAGE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_filename = Path(
        filename
    ).name

    if not safe_filename:
        safe_filename = "evidence.bin"

    file_hash = hashlib.sha256(
        file_bytes
    ).hexdigest()

    stored_filename = (
        f"{file_hash}_{safe_filename}"
    )

    destination = (
        EVIDENCE_STORAGE_DIR
        / stored_filename
    )

    destination.write_bytes(
        file_bytes
    )

    return save_evidence(
        db=db,
        incident_id=incident_id,
        evidence_type=evidence_type,
        title=(
            title
            or safe_filename
        ),
        description=(
            description
            or "Uploaded incident evidence."
        ),
        severity=severity,
        source=source,
        filename=safe_filename,
        stored_path=str(
            destination
        ),
        sha256=file_hash,
    )


def get_evidence(
    db: Session,
    incident_id: int,
) -> list[Evidence]:
    """
    Return all evidence belonging to an incident.
    """

    statement = (
        select(Evidence)
        .where(
            Evidence.incident_id
            == incident_id
        )
        .order_by(
            Evidence.created_at.desc()
        )
    )

    return list(
        db.scalars(
            statement
        ).all()
    )


def get_evidence_item(
    db: Session,
    evidence_id: int,
    incident_id: int,
) -> Evidence | None:
    """
    Return one evidence item belonging to
    the specified incident.
    """

    statement = (
        select(Evidence)
        .where(
            Evidence.id == evidence_id,
            Evidence.incident_id
            == incident_id,
        )
    )

    return db.scalar(
        statement
    )


def delete_evidence(
    db: Session,
    evidence_id: int,
    incident_id: int,
) -> bool:
    """
    Delete an evidence record and, when possible,
    delete its associated stored file.
    """

    evidence = get_evidence_item(
        db=db,
        evidence_id=evidence_id,
        incident_id=incident_id,
    )

    if evidence is None:
        return False

    stored_path = (
        evidence.stored_path
    )

    db.delete(evidence)
    db.commit()

    if stored_path:
        try:
            path = Path(
                stored_path
            )

            if path.exists():
                path.unlink()

        except OSError:
            # Database deletion has already succeeded.
            # A filesystem cleanup failure should not
            # make the API request fail.
            pass

    return True