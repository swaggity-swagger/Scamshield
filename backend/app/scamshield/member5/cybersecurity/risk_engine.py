"""Risk scoring for ScamShield."""

from __future__ import annotations

from typing import Any

from .rules import RISK_LEVELS, rule_for


RELATED_GROUPS = [
    {"otp_request", "pin_request", "password_request", "sensitive_personal_info_request"},
    {"payment_request", "money_transfer_request", "qr_payment_request"},
    {"bank_impersonation", "government_impersonation", "police_impersonation"},
    {"brand_sender_domain_mismatch", "brand_action_link_mismatch"},
    {"suspicious_url", "suspicious_domain", "url_shortener", "ip_based_url"},
    {"live_url_domain_redirect", "live_url_redirect_chain"},
    {"live_page_credential_form", "live_page_sensitive_data_request", "live_page_account_action_form", "live_page_brand_mismatch"},
    {"job_registration_fee", "job_security_deposit"},
]

CONTEXT_BONUSES = [
    (
        {"prize_lottery_claim", "unexpected_prize_offer"},
        {"qr_scam_call_to_action"},
        15,
        "Prize or giveaway language paired with a QR-driven action",
    ),
    (
        {"brand_prize_impersonation"},
        {"unexpected_prize_offer", "prize_lottery_claim"},
        7,
        "A brand name is used with an unexpected prize or reward",
    ),
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
    factors: list[dict[str, Any]] = []
    counted: set[str] = set()

    for group in RELATED_GROUPS:
        present = ids & group
        if present:
            strongest = max(rule_for(indicator_id)["weight"] for indicator_id in present)
            bonus = min(8, max(0, len(present) - 1) * 4)
            score += strongest + bonus
            factors.append({"type": "indicator_group", "indicator_ids": sorted(present), "score_impact": strongest + bonus})
            counted.update(present)

    for indicator_id in ids - counted:
        weight = int(rule_for(str(indicator_id))["weight"])
        score += weight
        factors.append({"type": "indicator", "indicator_id": indicator_id, "score_impact": weight})

    for first_group, second_group, bonus, reason in CONTEXT_BONUSES:
        if ids & first_group and ids & second_group:
            score += bonus
            factors.append({"type": "combined_context", "score_impact": bonus, "reason": reason})

    score = min(100, max(0, score))
    return {"risk_score": score, "risk_level": risk_level_for(score), "risk_factors": factors}
