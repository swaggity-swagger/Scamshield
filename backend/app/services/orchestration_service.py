from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.integrations.cybersecurity_adapter import analyze_security
from app.integrations.nlp_adapter import analyze_message
from app.integrations.ocr_adapter import extract_image
from app.integrations.qr_adapter import decode_image_qr
from app.models.incident import Incident
from app.schemas.timeline import TimelineCreate
from app.services.analysis_service import save_analysis
from app.services.report_service import create_or_update_report
from app.services.threat_finding_service import save_threat_findings
from app.services.threat_intelligence import lookup_indicator
from app.services.timeline_service import create_timeline_event
from app.services.url_service import analyze_url


def _jsonable(value: Any) -> Any:
    """
    Convert Pydantic/model values into JSON-compatible Python values.
    """

    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump())

    if isinstance(value, dict):
        return {
            str(key): _jsonable(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            _jsonable(item)
            for item in value
        ]

    return value


def _add_timeline(
    db: Session,
    incident_id: int,
    event_type: str,
    description: str,
) -> None:
    """
    Add an event to the incident timeline.
    """

    create_timeline_event(
        db=db,
        incident_id=incident_id,
        data=TimelineCreate(
            event_time=datetime.utcnow(),
            event_type=event_type,
            description=description,
        ),
    )


def _risk_level(score: int) -> str:
    """
    Convert a numeric risk score into a risk level.
    """

    if score >= 70:
        return "critical"

    if score >= 45:
        return "high"

    if score >= 20:
        return "medium"

    return "low"


def _collect_urls(
    cybersecurity: dict[str, Any],
) -> list[str]:
    """
    Extract unique URLs from cybersecurity analysis.
    """

    urls: list[str] = []

    url_analysis = (
        cybersecurity.get("url_analysis")
        or []
    )

    for item in url_analysis:
        if isinstance(item, dict):
            url = item.get("url")

            if url and url not in urls:
                urls.append(str(url))

    return urls


async def _run_threat_intelligence(
    urls: list[str],
) -> list[dict[str, Any]]:
    """
    Query configured threat-intelligence providers.

    External TI failures do not fail the complete analysis.
    """

    findings: list[dict[str, Any]] = []

    seen: set[tuple[str, str]] = set()

    for url in urls:
        key = (
            url,
            "url",
        )

        if key in seen:
            continue

        seen.add(key)

        try:
            results = await lookup_indicator(
                indicator=url,
                indicator_type="url",
            )

        except Exception:
            continue

        for result in results:
            findings.append(
                {
                    "indicator": url,
                    "indicator_type": "url",
                    "source": result.get(
                        "source",
                        "unknown",
                    ),
                    "verdict": result.get(
                        "verdict"
                    ),
                    "confidence": result.get(
                        "confidence"
                    ),
                    "summary": result.get(
                        "summary"
                    ),
                    "raw_data": result.get(
                        "raw_data"
                    ),
                }
            )

    return findings


def _build_final_result(
    incident_id: int,
    source_type: str,
    text: str,
    nlp: dict[str, Any],
    cybersecurity: dict[str, Any],
    threat_findings: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    """
    Normalize NLP + cybersecurity + threat-intelligence
    results into the structure consumed by the backend.
    """

    nlp = _jsonable(nlp)
    cybersecurity = _jsonable(cybersecurity)

    # ---------------------------------------------------------
    # Risk
    # ---------------------------------------------------------

    risk_score = cybersecurity.get(
        "risk_score"
    )

    if risk_score is None:
        risk_score = nlp.get(
            "risk_score",
            0,
        )

    try:
        risk_score = int(
            float(risk_score)
        )

    except (
        TypeError,
        ValueError,
    ):
        risk_score = 0

    risk_score = max(
        0,
        min(
            100,
            risk_score,
        ),
    )

    risk_level = (
        cybersecurity.get(
            "risk_level"
        )
        or nlp.get(
            "risk_level"
        )
        or _risk_level(
            risk_score
        )
    )

    risk_level = str(
        risk_level
    ).lower()

    # ---------------------------------------------------------
    # Scam category
    # ---------------------------------------------------------

    scam_type = cybersecurity.get(
        "scam_type"
    )

    if scam_type:
        categories = [
            str(scam_type)
        ]

    else:
        categories = (
            cybersecurity.get(
                "scam_categories"
            )
            or nlp.get(
                "scam_categories"
            )
            or []
        )

    if isinstance(
        categories,
        str,
    ):
        categories = [
            categories
        ]

    # ---------------------------------------------------------
    # Confidence
    # ---------------------------------------------------------

    confidence = (
        cybersecurity.get(
            "confidence"
        )
        or nlp.get(
            "confidence",
            0,
        )
    )

    try:
        confidence = int(
            float(confidence)
        )

    except (
        TypeError,
        ValueError,
    ):
        confidence = 0

    confidence = max(
        0,
        min(
            100,
            confidence,
        ),
    )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    summary = (
        nlp.get(
            "summary"
        )
        or cybersecurity.get(
            "summary"
        )
        or "Analysis completed."
    )

    # ---------------------------------------------------------
    # Recommendations
    # ---------------------------------------------------------

    recommendations = (
        cybersecurity.get(
            "recommendations"
        )
        or nlp.get(
            "recommended_actions"
        )
        or []
    )

    # ---------------------------------------------------------
    # Evidence
    # ---------------------------------------------------------

    evidence = _jsonable(
        nlp.get(
            "evidence"
        )
        or []
    )

    indicators = _jsonable(
        cybersecurity.get(
            "indicators"
        )
        or []
    )

    # ---------------------------------------------------------
    # URLs
    # ---------------------------------------------------------

    urls = _collect_urls(
        cybersecurity
    )

    # ---------------------------------------------------------
    # Threat-intelligence escalation
    # ---------------------------------------------------------

    for finding in threat_findings:
        verdict = str(
            finding.get(
                "verdict"
            )
            or ""
        ).lower()

        if verdict in {
            "malicious",
            "confirmed_malicious",
        }:
            risk_score = max(
                risk_score,
                90,
            )

            risk_level = "critical"

    return {
        "status": (
            "partial"
            if warnings
            else "completed"
        ),
        "incident_id": incident_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "detected_language": nlp.get(
            "detected_language"
        ),
        "scam_categories": categories,
        "summary": summary,
        "evidence": evidence,
        "indicators": indicators,
        "recommended_actions": recommendations,
        "safe_to_interact": (
            risk_score < 45
        ),
        "source_type": source_type,
        "extracted_text": text,
        "urls": urls,
        "qr_data": [],
        "upi_ids": [],
        "threat_findings": threat_findings,
        "warnings": warnings,
        "cybersecurity_analysis": cybersecurity,
        "ai_response": {
            "available": bool(nlp),
            "nlp_assessment": nlp,
        },
    }


async def _run_common_pipeline(
    db: Session,
    incident: Incident,
    source_type: str,
    extracted: dict[str, Any],
    preferred_language: str = "en",
) -> dict[str, Any]:
    """
    Common ScamShield analysis pipeline.

    extracted can contain:
        text
        urls
        qr_data
        upi_ids
    """

    warnings: list[str] = []

    text = (
        extracted.get("text")
        or ""
    )

    urls = list(
        extracted.get("urls")
        or []
    )

    qr_data = list(
        extracted.get("qr_data")
        or []
    )

    upi_ids = list(
        extracted.get("upi_ids")
        or []
    )

    # ---------------------------------------------------------
    # ANALYSIS STARTED
    # ---------------------------------------------------------

    _add_timeline(
        db,
        incident.id,
        "ANALYSIS_STARTED",
        f"{source_type} analysis started.",
    )

    incident.status = "in_progress"

    db.commit()
    db.refresh(incident)

    # ---------------------------------------------------------
    # NLP
    # ---------------------------------------------------------

    nlp: dict[str, Any] = {}

    if text.strip():
        try:
            nlp = analyze_message(
                text,
                preferred_language,
            )

            _add_timeline(
                db,
                incident.id,
                "NLP_COMPLETED",
                "Multilingual NLP analysis completed.",
            )

        except Exception as exc:
            warnings.append(
                f"NLP analysis failed: {exc}"
            )

    # ---------------------------------------------------------
    # CYBERSECURITY
    # ---------------------------------------------------------

    cybersecurity: dict[str, Any] = {}

    try:
        cybersecurity = analyze_security(
            text=text or None,
            urls=urls or None,
            qr_data=qr_data or None,
            upi_data=upi_ids or None,
        )

        cybersecurity = _jsonable(
            cybersecurity
        )

        _add_timeline(
            db,
            incident.id,
            "CYBERSECURITY_COMPLETED",
            "Cybersecurity analysis completed.",
        )

    except Exception as exc:
        warnings.append(
            f"Cybersecurity analysis failed: {exc}"
        )

    # ---------------------------------------------------------
    # DISCOVER ADDITIONAL URLS
    # ---------------------------------------------------------

    discovered_urls = list(
        urls
    )

    for item in (
        cybersecurity.get(
            "url_analysis"
        )
        or []
    ):
        if isinstance(
            item,
            dict,
        ):
            url = item.get(
                "url"
            )

            if (
                url
                and url not in discovered_urls
            ):
                discovered_urls.append(
                    str(url)
                )

    extracted["urls"] = list(
        dict.fromkeys(
            discovered_urls
        )
    )

    # ---------------------------------------------------------
    # THREAT INTELLIGENCE
    # ---------------------------------------------------------

    threat_findings: list[
        dict[str, Any]
    ] = []

    if extracted["urls"]:
        threat_findings = (
            await _run_threat_intelligence(
                extracted["urls"]
            )
        )

        if threat_findings:
            _add_timeline(
                db,
                incident.id,
                "THREAT_INTELLIGENCE_COMPLETED",
                "Threat-intelligence checks completed.",
            )

    # ---------------------------------------------------------
    # FINAL RESULT
    # ---------------------------------------------------------

    result = _build_final_result(
        incident_id=incident.id,
        source_type=source_type,
        text=text,
        nlp=nlp,
        cybersecurity=cybersecurity,
        threat_findings=threat_findings,
        warnings=warnings,
    )

    # ---------------------------------------------------------
    # SAVE ANALYSIS + EVIDENCE
    # ---------------------------------------------------------

    save_analysis(
        db=db,
        incident_id=incident.id,
        analysis_type=source_type,
        result=result,
    )

    # ---------------------------------------------------------
    # SAVE THREAT FINDINGS
    # ---------------------------------------------------------

    if threat_findings:
        save_threat_findings(
            db=db,
            incident_id=incident.id,
            findings=threat_findings,
        )

    # ---------------------------------------------------------
    # UPDATE INCIDENT
    # ---------------------------------------------------------

    incident.status = result[
        "status"
    ]

    categories = (
        result.get(
            "scam_categories"
        )
        or []
    )

    incident.analysis_category = (
        str(categories[0])
        if categories
        else None
    )

    incident.analysis_risk_level = (
        result[
            "risk_level"
        ]
    )

    incident.analysis_summary = (
        result[
            "summary"
        ]
    )

    db.commit()
    db.refresh(incident)

    # ---------------------------------------------------------
    # ANALYSIS COMPLETED
    # ---------------------------------------------------------

    _add_timeline(
        db,
        incident.id,
        "ANALYSIS_COMPLETED",
        f"{source_type} analysis completed.",
    )

    # ---------------------------------------------------------
    # REPORT GENERATION
    # ---------------------------------------------------------

    try:
        report = create_or_update_report(
            db=db,
            incident_id=incident.id,
        )

        incident.status = "reported"

        db.commit()
        db.refresh(incident)

        _add_timeline(
            db,
            incident.id,
            "REPORT_GENERATED",
            "Incident report generated successfully.",
        )

        result["report"] = {
            "id": report.id,
            "summary": report.summary,
            "recommendation": report.recommendation,
        }

    except Exception as exc:
        result["status"] = "partial"

        incident.status = "completed"

        result.setdefault(
            "warnings",
            [],
        ).append(
            f"Report generation failed: {exc}"
        )

        db.commit()
        db.refresh(incident)

    return result


async def run_text_analysis(
    db: Session,
    incident: Incident,
    text: str,
    preferred_language: str = "en",
) -> dict[str, Any]:
    """
    Run text through the common ScamShield pipeline.
    """

    extracted = {
        "text": text,
        "urls": [],
        "qr_data": [],
        "upi_ids": [],
    }

    return await _run_common_pipeline(
        db=db,
        incident=incident,
        source_type="text",
        extracted=extracted,
        preferred_language=preferred_language,
    )


async def run_url_analysis(
    db: Session,
    incident: Incident,
    url: str,
    preferred_language: str = "en",
) -> dict[str, Any]:
    """
    Run direct URL analysis and then the common pipeline.
    """

    warnings: list[str] = []

    direct_url_analysis: dict[str, Any] = {}

    try:
        direct_url_analysis = analyze_url(
            url,
            preferred_language,
        )

    except Exception as exc:
        warnings.append(
            f"URL analysis failed: {exc}"
        )

    extracted = {
        "text": "",
        "urls": [url],
        "qr_data": [],
        "upi_ids": [],
    }

    result = await _run_common_pipeline(
        db=db,
        incident=incident,
        source_type="url",
        extracted=extracted,
        preferred_language=preferred_language,
    )

    result["raw_metadata"] = {
        "direct_url_analysis": _jsonable(
            direct_url_analysis
        )
    }

    if warnings:
        result.setdefault(
            "warnings",
            [],
        ).extend(warnings)

        result["status"] = "partial"

    return result


async def run_image_analysis(
    db: Session,
    incident: Incident,
    image_bytes: bytes,
    preferred_language: str = "en",
) -> dict[str, Any]:
    """
    Analyze a screenshot/image using OCR and QR extraction.
    """

    extracted = {
        "text": "",
        "urls": [],
        "qr_data": [],
        "upi_ids": [],
    }

    warnings: list[str] = []

    # ---------------------------------------------------------
    # OCR
    # ---------------------------------------------------------

    try:
        ocr_result = extract_image(
            image_bytes
        )

        extracted["text"] = (
            ocr_result.get(
                "text"
            )
            or ""
        )

        extracted["urls"].extend(
            ocr_result.get(
                "urls"
            )
            or []
        )

        extracted["upi_ids"].extend(
            ocr_result.get(
                "upi_ids"
            )
            or []
        )

        _add_timeline(
            db,
            incident.id,
            "OCR_COMPLETED",
            "Screenshot OCR completed.",
        )

    except Exception as exc:
        warnings.append(
            f"OCR analysis failed: {exc}"
        )

    # ---------------------------------------------------------
    # QR
    # ---------------------------------------------------------

    try:
        qr_result = decode_image_qr(
            image_bytes
        )

        if qr_result.get(
            "qr_detected"
        ):
            extracted["qr_data"].extend(
                qr_result.get(
                    "qr_data"
                )
                or []
            )

            extracted["urls"].extend(
                qr_result.get(
                    "urls"
                )
                or []
            )

            extracted["upi_ids"].extend(
                qr_result.get(
                    "upi_ids"
                )
                or []
            )

            qr_text = (
                qr_result.get(
                    "text"
                )
                or ""
            )

            if qr_text:
                if extracted["text"]:
                    extracted["text"] += (
                        "\n"
                        + qr_text
                    )
                else:
                    extracted["text"] = (
                        qr_text
                    )

            _add_timeline(
                db,
                incident.id,
                "QR_DECODED",
                "QR code detected and decoded.",
            )

    except ValueError:
        # No QR is normal for an ordinary screenshot.
        pass

    except Exception as exc:
        warnings.append(
            f"QR analysis failed: {exc}"
        )

    # ---------------------------------------------------------
    # Remove duplicates
    # ---------------------------------------------------------

    extracted["urls"] = list(
        dict.fromkeys(
            extracted["urls"]
        )
    )

    extracted["qr_data"] = list(
        dict.fromkeys(
            extracted["qr_data"]
        )
    )

    extracted["upi_ids"] = list(
        dict.fromkeys(
            extracted["upi_ids"]
        )
    )

    # ---------------------------------------------------------
    # Common pipeline
    # ---------------------------------------------------------

    result = await _run_common_pipeline(
        db=db,
        incident=incident,
        source_type="image",
        extracted=extracted,
        preferred_language=preferred_language,
    )

    if warnings:
        result.setdefault(
            "warnings",
            [],
        ).extend(warnings)

        result["status"] = "partial"

    return result


async def run_qr_analysis(
    db: Session,
    incident: Incident,
    image_bytes: bytes,
    preferred_language: str = "en",
) -> dict[str, Any]:
    """
    Decode and analyze a dedicated QR-code image.
    """

    try:
        qr_result = decode_image_qr(
            image_bytes
        )

    except Exception as exc:
        raise ValueError(
            f"QR decoding failed: {exc}"
        ) from exc

    if not qr_result.get(
        "qr_detected"
    ):
        raise ValueError(
            "No QR code was detected."
        )

    extracted = {
        "text": (
            qr_result.get(
                "text"
            )
            or ""
        ),
        "urls": list(
            dict.fromkeys(
                qr_result.get(
                    "urls"
                )
                or []
            )
        ),
        "qr_data": list(
            dict.fromkeys(
                qr_result.get(
                    "qr_data"
                )
                or []
            )
        ),
        "upi_ids": list(
            dict.fromkeys(
                qr_result.get(
                    "upi_ids"
                )
                or []
            )
        ),
    }

    _add_timeline(
        db,
        incident.id,
        "QR_DECODED",
        "QR code decoded successfully.",
    )

    return await _run_common_pipeline(
        db=db,
        incident=incident,
        source_type="qr",
        extracted=extracted,
        preferred_language=preferred_language,
    )