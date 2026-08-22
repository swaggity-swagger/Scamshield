"""Risk scoring for ScamShield."""

from __future__ import annotations

from typing import Any

from .rules import RISK_LEVELS, rule_for


RELATED_GROUPS = [
    {"otp_request", "pin_request", "password_request", "sensitive_personal_info_request"},
    {"payment_request", "money_transfer_request", "qr_payment_request"},
    {"bank_impersonation", "government_impersonation", "police_impersonation"},
    {"suspicious_url", "suspicious_domain", "url_shortener", "ip_based_url"},
    {"job_registration_fee", "job_security_deposit"},
]


def risk_level_for(score: int) -> str:
    """Map numeric risk score to a risk label."""
    for max_score, level in RISK_LEVELS:
        if score <= max_score:
            return level
    return "VERY HIGH"


def calculate_risk(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate a capped prototype risk score from indicator IDs."""
    ids = {item.get("id") for item in indicators if item.get("id")}
    score = 0
    counted: set[str] = set()

    for group in RELATED_GROUPS:
        present = ids & group
        if present:
            strongest = max(rule_for(indicator_id)["weight"] for indicator_id in present)
            bonus = min(8, max(0, len(present) - 1) * 4)
            score += strongest + bonus
            counted.update(present)

    for indicator_id in ids - counted:
        score += int(rule_for(str(indicator_id))["weight"])

    score = min(100, max(0, score))
    return {"risk_score": score, "risk_level": risk_level_for(score)}
