"""Public ScamShield cybersecurity analysis interface."""

from __future__ import annotations

import re
from typing import Any

from .detector import detect_indicators
from .email_analyzer import analyze_email_context
from .recommendations import generate_recommendations
from .risk_engine import calculate_risk
from .scam_classifier import classify_scam
from .threat_intelligence import check_domain_reputation, check_url_reputation
from .upi_analyzer import UPI_ID_RE, analyze_upi
from .url_analyzer import analyze_url


URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>'\"]+", flags=re.IGNORECASE)


def _as_list(value: str | list[str] | tuple[str, ...] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value if item]


def _dedupe_indicators(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in indicators:
        indicator_id = str(item.get("id"))
        if indicator_id and indicator_id not in seen:
            deduped.append(item)
            seen.add(indicator_id)
    return deduped


def _extract_urls(*texts: str | None) -> list[str]:
    urls: list[str] = []
    for text in texts:
        if not text:
            continue
        urls.extend(match.group(0).rstrip(".,)") for match in URL_RE.finditer(text))
    return urls


def analyze_input(
    text: str | None = None,
    urls: list[str] | str | None = None,
    qr_data: list[str] | str | None = None,
    upi_data: dict[str, Any] | str | None = None,
    qr_detected: bool = False,
) -> dict[str, Any]:
    """Analyze content supplied by OCR/QR/backend modules.

    Integration contract:
    OCR/QR teammates can call this single function with extracted text, URLs,
    decoded QR payloads, and UPI data. They do not need to modify internal
    cybersecurity modules. AI/NLP modules can consume this structured output
    later, but this function does not run any AI or LLM logic.
    """
    qr_items = _as_list(qr_data)
    qr_present = qr_detected or bool(qr_items)
    text_indicators = detect_indicators(text, qr_detected=qr_present, qr_decoded=bool(qr_items))

    all_urls = _as_list(urls)
    all_urls.extend(_extract_urls(text, *qr_items))
    seen_urls: set[str] = set()
    url_results = []
    for url in all_urls:
        if url not in seen_urls:
            url_results.append(analyze_url(url))
            seen_urls.add(url)

    email_analysis = analyze_email_context(text, all_urls)

    threat_intel_results = []
    for url_result in url_results:
        threat_intel_results.append(check_url_reputation(url_result["url"]))
        domain = url_result.get("domain")
        if domain:
            threat_intel_results.append(check_domain_reputation(domain))

    upi_results: list[dict[str, Any]] = []
    if upi_data:
        upi_results.append(analyze_upi(upi_data, context_text=text))
    for qr_item in qr_items:
        if str(qr_item).lower().startswith("upi://") or UPI_ID_RE.search(str(qr_item)):
            upi_results.append(analyze_upi(qr_item, context_text=text))

    combined_indicators = list(text_indicators)
    combined_indicators.extend(email_analysis["indicators"])
    for result in url_results:
        combined_indicators.extend(result.get("indicators", []))
    for result in upi_results:
        combined_indicators.extend(result.get("indicators", []))
    indicators = _dedupe_indicators(combined_indicators)

    risk = calculate_risk(indicators)
    primary_upi = upi_results[0] if upi_results else {}
    classification = classify_scam(indicators, urls=url_results, upi=primary_upi, text=text)
    recommendations = generate_recommendations(classification["scam_type"], indicators)

    return {
        **risk,
        **classification,
        "indicators": indicators,
        "url_analysis": url_results,
        "email_analysis": email_analysis,
        "upi_analysis": primary_upi,
        "upi_analysis_results": upi_results,
        "qr_data": qr_items,
        "qr_detected": qr_present,
        "threat_intelligence": threat_intel_results,
        "recommendations": recommendations,
    }
