from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence import Evidence


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
):
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


def get_evidence(
    db: Session,
    incident_id: int,
):
    statement = (
        select(Evidence)
        .where(
            Evidence.incident_id == incident_id
        )
        .order_by(
            Evidence.created_at.desc()
        )
    )

    return db.scalars(statement).all()