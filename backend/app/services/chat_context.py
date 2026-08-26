import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.analysis_result import AnalysisResult
from app.models.evidence import Evidence
from app.models.threat_finding import ThreatFinding


def build_incident_context(
    db: Session,
    incident_id: int,
    user_id: int,
) -> str | None:

    incident = db.scalar(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.user_id == user_id,
        )
    )

    if incident is None:
        return None

    analyses = db.scalars(
        select(AnalysisResult).where(
            AnalysisResult.incident_id
            == incident_id
        )
    ).all()

    evidence = db.scalars(
        select(Evidence).where(
            Evidence.incident_id
            == incident_id
        )
    ).all()

    threats = db.scalars(
        select(ThreatFinding).where(
            ThreatFinding.incident_id
            == incident_id
        )
    ).all()

    context = {
        "incident": {
            "type": incident.incident_type,
            "description": incident.description,
        },
        "analyses": [
            {
                "type": item.analysis_type,
                "risk_score": item.risk_score,
                "risk_level": item.risk_level,
                "confidence": item.confidence,
            }
            for item in analyses
        ],
        "evidence": [
            {
                "title": item.title,
                "description": item.description,
                "severity": item.severity,
                "source": item.source,
            }
            for item in evidence
        ],
        "threat_findings": [
            {
                "indicator": item.indicator,
                "indicator_type": item.indicator_type,
                "source": item.source,
                "verdict": item.verdict,
                "confidence": item.confidence,
                "summary": item.summary,
            }
            for item in threats
        ],
    }

    return json.dumps(
        context,
        ensure_ascii=False,
    )