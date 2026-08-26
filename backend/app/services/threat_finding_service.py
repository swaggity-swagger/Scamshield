from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_finding import ThreatFinding


def save_threat_findings(
    db: Session,
    incident_id: int,
    findings: list[dict],
) -> list[ThreatFinding]:
    """
    Save threat-intelligence findings for an incident.

    Duplicate indicators from the same source are skipped.
    """

    saved: list[ThreatFinding] = []

    existing_statement = select(ThreatFinding).where(
        ThreatFinding.incident_id == incident_id
    )

    existing = db.scalars(
        existing_statement
    ).all()

    existing_keys = {
        (
            item.indicator,
            item.indicator_type,
            item.source,
        )
        for item in existing
    }

    for item in findings:
        indicator = item.get("indicator")

        if not indicator:
            continue

        indicator_type = str(
            item.get(
                "indicator_type",
                "unknown",
            )
        )

        source = str(
            item.get(
                "source",
                "unknown",
            )
        )

        key = (
            str(indicator),
            indicator_type,
            source,
        )

        if key in existing_keys:
            continue

        finding = ThreatFinding(
            incident_id=incident_id,
            indicator=str(indicator),
            indicator_type=indicator_type,
            source=source,
            verdict=item.get("verdict"),
            confidence=item.get("confidence"),
            summary=item.get("summary"),
            raw_data=item.get("raw_data"),
        )

        db.add(finding)
        saved.append(finding)
        existing_keys.add(key)

    db.flush()

    return saved