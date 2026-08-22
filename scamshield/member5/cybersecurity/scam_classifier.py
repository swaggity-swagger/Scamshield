"""Scam classification from deterministic signals."""

from __future__ import annotations

from typing import Any


SCAM_TYPES = {
    "PHISHING",
    "SMISHING",
    "QR_SCAM",
    "UPI_SCAM",
    "JOB_SCAM",
    "INVESTMENT_SCAM",
    "IMPERSONATION",
    "OTP_SCAM",
    "PAYMENT_SCAM",
    "PRIZE_SCAM",
    "REFUND_SCAM",
    "NORMAL_OR_UNKNOWN",
}


def classify_scam(
    indicators: list[dict[str, Any]],
    urls: list[dict[str, Any]] | None = None,
    upi: dict[str, Any] | None = None,
    text: str | None = None,
) -> dict[str, Any]:
    """Return the most likely scam category from cybersecurity indicators."""
    ids = {item.get("id") for item in indicators}
    text_l = (text or "").lower()
    scores = {scam_type: 0.0 for scam_type in SCAM_TYPES}

    if {"otp_request", "pin_request"} & ids:
        scores["OTP_SCAM"] += 0.75
    if {"password_request", "kyc_request", "account_blocking_threat", "suspicious_url", "brand_sender_domain_mismatch", "brand_action_link_mismatch", "credential_link_action"} & ids:
        scores["PHISHING"] += 0.35
    if "sms" in text_l or len(text_l) < 220:
        scores["SMISHING"] += 0.08 if ids else 0
    if {"bank_impersonation", "government_impersonation", "police_impersonation"} & ids:
        scores["IMPERSONATION"] += 0.55
        scores["PHISHING"] += 0.15
    if {"job_registration_fee", "job_security_deposit"} & ids:
        scores["JOB_SCAM"] += 0.78
    if "guaranteed_investment_returns" in ids:
        scores["INVESTMENT_SCAM"] += 0.78
    if {"prize_lottery_claim", "unexpected_prize_offer"} & ids:
        scores["PRIZE_SCAM"] += 0.72
    if "refund_scam" in ids:
        scores["REFUND_SCAM"] += 0.65
    if {"payment_request", "money_transfer_request"} & ids:
        scores["PAYMENT_SCAM"] += 0.38
    if {"unknown_upi_id", "qr_payment_request"} & ids or (upi and upi.get("risk_score", 0) >= 25):
        scores["UPI_SCAM"] += 0.58
    if {"qr_payment_request", "qr_scam_call_to_action"} & ids:
        scores["QR_SCAM"] += 0.72
    if urls:
        risky_urls = [item for item in urls if item.get("risk_score", 0) >= 25]
        if risky_urls:
            scores["PHISHING"] += 0.45

    scam_type, score = max(scores.items(), key=lambda item: item[1])
    if score <= 0:
        return {"scam_type": "NORMAL_OR_UNKNOWN"}

    return {"scam_type": scam_type}
