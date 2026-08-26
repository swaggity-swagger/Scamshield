from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analysis_result import AnalysisResult
from app.models.evidence import Evidence
from app.models.report import Report
from app.models.threat_finding import ThreatFinding


def risk_level_from_score(
    score: float,
) -> str:

    if score >= 75:
        return "critical"

    if score >= 50:
        return "high"

    if score >= 25:
        return "medium"

    return "low"


def build_incident_summary(
    db: Session,
    incident_id: int,
):

    analyses = db.scalars(
        select(AnalysisResult)
        .where(
            AnalysisResult.incident_id
            == incident_id
        )
        .order_by(
            AnalysisResult.created_at.desc()
        )
    ).all()

    evidence = db.scalars(
        select(Evidence)
        .where(
            Evidence.incident_id
            == incident_id
        )
        .order_by(
            Evidence.created_at.desc()
        )
    ).all()

    findings = db.scalars(
        select(ThreatFinding)
        .where(
            ThreatFinding.incident_id
            == incident_id
        )
        .order_by(
            ThreatFinding.created_at.desc()
        )
    ).all()

    # Prefer the unified workflow result.
    combined = next(
        (
            item
            for item in analyses
            if item.analysis_type
            == "combined"
        ),
        None,
    )

    cybersecurity = next(
        (
            item
            for item in analyses
            if item.analysis_type
            == "cybersecurity"
        ),
        None,
    )

    nlp = next(
        (
            item
            for item in analyses
            if item.analysis_type
            == "nlp"
        ),
        None,
    )

    primary = (
        combined
        or cybersecurity
        or nlp
        or (
            analyses[0]
            if analyses
            else None
        )
    )

    score = (
        primary.risk_score
        if primary
        and primary.risk_score is not None
        else 0
    )

    level = (
        primary.risk_level
        if primary
        and primary.risk_level
        else risk_level_from_score(
            score
        )
    )

    result_json = (
        primary.result_json
        if primary
        else {}
    )

    summary = (
        result_json.get("summary")
        or result_json.get(
            "ai_response",
            {},
        ).get("summary")
        or (
            "The submitted content was "
            "analyzed for scam indicators."
        )
    )

    recommendations = (
        result_json.get(
            "recommended_actions"
        )
        or result_json.get(
            "recommendations"
        )
        or result_json.get(
            "ai_response",
            {},
        ).get(
            "recommended_actions",
            [],
        )
    )

    if not recommendations:
        if level in {
            "high",
            "critical",
        }:
            recommendations = [
                "Do not click suspicious links.",
                "Do not share OTP, PIN or passwords.",
                "Verify through an official channel.",
                "Report the incident if necessary.",
            ]
        else:
            recommendations = [
                "Verify the information through an official source."
            ]

    safe_to_interact = result_json.get(
        "safe_to_interact"
    )

    if safe_to_interact is None:
        safe_to_interact = (
            level not in {
                "high",
                "critical",
            }
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "summary": summary,
        "recommendations": recommendations,
        "safe_to_interact": safe_to_interact,
        "analysis_count": len(analyses),
        "evidence_count": len(evidence),
        "threat_finding_count": len(findings),
        "analyses": [
            {
                "type": item.analysis_type,
                "risk_score": item.risk_score,
                "risk_level": item.risk_level,
                "confidence": item.confidence,
                "result": item.result_json,
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
            for item in findings
        ],
    }


def create_or_update_report(
    db: Session,
    incident_id: int,
):

    summary = build_incident_summary(
        db,
        incident_id,
    )

    report = db.scalar(
        select(Report).where(
            Report.incident_id
            == incident_id
        )
    )

    if report is None:

        report = Report(
            incident_id=incident_id,
            summary=summary["summary"],
            recommendation="\n".join(
                summary["recommendations"]
            ),
            report_data=summary,
        )

        db.add(report)

    else:

        report.summary = summary[
            "summary"
        ]

        report.recommendation = "\n".join(
            summary["recommendations"]
        )

        report.report_data = summary

    db.commit()
    db.refresh(report)

    return report