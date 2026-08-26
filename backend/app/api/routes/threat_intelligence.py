from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.models.threat_finding import ThreatFinding
from app.schemas.threat_intel import (
    ThreatLookupRequest,
)
from app.services.incident_service import (
    get_user_incident,
)
from app.services.threat_intelligence import (
    lookup_indicator,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Threat Intelligence"],
)


@router.post(
    "/{incident_id}/threat-intelligence"
)
async def enrich_incident(
    incident_id: int,
    data: ThreatLookupRequest,
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

    results = await lookup_indicator(
        data.indicator,
        data.indicator_type,
    )

    saved = []

    for item in results:

        finding = ThreatFinding(
            incident_id=incident_id,
            indicator=data.indicator,
            indicator_type=data.indicator_type,
            source=item["source"],
            verdict=item.get("verdict"),
            confidence=item.get(
                "confidence"
            ),
            summary=item.get(
                "summary"
            ),
            raw_data=item.get(
                "raw_data"
            ),
        )

        db.add(finding)
        saved.append(item)

    db.commit()

    return {
        "incident_id": incident_id,
        "indicator": data.indicator,
        "findings": saved,
    }