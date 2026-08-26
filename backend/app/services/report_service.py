from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analysis_result import AnalysisResult
from app.models.evidence import Evidence
from app.models.report import Report
from app.models.threat_finding import ThreatFinding


# ============================================================
# RISK LEVEL
# ============================================================

def risk_level_from_score(
    score: float,
) -> str:
    """
    Convert a numeric risk score to the standard
    ScamShield risk level.

    Thresholds:
        0-19   -> low
        20-44  -> medium
        45-69  -> high
        70-100 -> critical
    """

    if score >= 70:
        return "critical"

    if score >= 45:
        return "high"

    if score >= 20:
        return "medium"

    return "low"


# ============================================================
# BUILD INCIDENT SUMMARY FOR REPORT
# ============================================================

def build_incident_summary(
    db: Session,
    incident_id: int,
) -> dict[str, Any]:
    """
    Build the core analysis summary used by reports.

    This function collects:
        - analysis results
        - evidence
        - threat findings

    The newest combined/cybersecurity/NLP/general analysis
    is used as the primary analysis source.
    """

    # ---------------------------------------------------------
    # ANALYSES
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # EVIDENCE
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # THREAT FINDINGS
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # SELECT PRIMARY ANALYSIS
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # RISK
    # ---------------------------------------------------------

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

    level = str(
        level
    ).lower()

    # ---------------------------------------------------------
    # RESULT JSON
    # ---------------------------------------------------------

    result_json = (
        primary.result_json
        if primary
        and primary.result_json
        else {}
    )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    summary = (
        result_json.get(
            "summary"
        )
        or result_json.get(
            "ai_response",
            {},
        ).get(
            "summary"
        )
        or (
            "The submitted content was "
            "analyzed for scam indicators."
        )
    )

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

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

    if isinstance(
        recommendations,
        str,
    ):
        recommendations = [
            recommendations
        ]

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

    # ---------------------------------------------------------
    # SAFE TO INTERACT
    # ---------------------------------------------------------

    safe_to_interact = (
        result_json.get(
            "safe_to_interact"
        )
    )

    if safe_to_interact is None:
        safe_to_interact = (
            score < 45
        )

    # ---------------------------------------------------------
    # FINAL REPORT SUMMARY
    # ---------------------------------------------------------

    return {
        "risk_score": score,
        "risk_level": level,
        "summary": summary,
        "recommendations": recommendations,
        "safe_to_interact": safe_to_interact,
        "analysis_count": len(
            analyses
        ),
        "evidence_count": len(
            evidence
        ),
        "threat_finding_count": len(
            findings
        ),
        "analyses": [
            {
                "id": item.id,
                "type": item.analysis_type,
                "risk_score": item.risk_score,
                "risk_level": item.risk_level,
                "confidence": item.confidence,
                "result": item.result_json,
                "created_at": item.created_at,
            }
            for item in analyses
        ],
        "evidence": [
            {
                "id": item.id,
                "title": item.title,
                "description": item.description,
                "severity": item.severity,
                "source": item.source,
                "evidence_type": item.evidence_type,
                "filename": item.filename,
                "stored_path": item.stored_path,
                "sha256": item.sha256,
                "created_at": item.created_at,
            }
            for item in evidence
        ],
        "threat_findings": [
            {
                "id": item.id,
                "indicator": item.indicator,
                "indicator_type": item.indicator_type,
                "source": item.source,
                "verdict": item.verdict,
                "confidence": item.confidence,
                "summary": item.summary,
                "created_at": item.created_at,
            }
            for item in findings
        ],
    }


# ============================================================
# CREATE OR UPDATE REPORT
# ============================================================

def create_or_update_report(
    db: Session,
    incident_id: int,
) -> Report:
    """
    Create a report for an incident if one does not exist,
    otherwise update the existing report.

    Reports are generated from the latest stored analysis,
    evidence and threat-intelligence findings.
    """

    summary = build_incident_summary(
        db=db,
        incident_id=incident_id,
    )

    report = db.scalar(
        select(Report)
        .where(
            Report.incident_id
            == incident_id
        )
    )

    recommendation = "\n".join(
        str(item)
        for item in summary.get(
            "recommendations",
            [],
        )
    )

    if report is None:
        report = Report(
            incident_id=incident_id,
            summary=summary[
                "summary"
            ],
            recommendation=recommendation,
            report_data=summary,
        )

        db.add(report)

    else:
        report.summary = summary[
            "summary"
        ]

        report.recommendation = (
            recommendation
        )

        report.report_data = summary

    db.commit()
    db.refresh(report)

    return report