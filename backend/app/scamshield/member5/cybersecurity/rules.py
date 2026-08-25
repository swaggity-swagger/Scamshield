"""Central prototype rule configuration for ScamShield.

Weights are initial engineering heuristics for a first version. They are not
scientifically validated and should be tuned with real-world evaluation data.
"""

from __future__ import annotations

from typing import Any


INDICATOR_RULES: dict[str, dict[str, Any]] = {
    "otp_request": {"label": "OTP request", "severity": "very_high", "weight": 30},
    "pin_request": {"label": "PIN request", "severity": "very_high", "weight": 32},
    "password_request": {"label": "Password request", "severity": "very_high", "weight": 28},
    "payment_request": {"label": "Payment request", "severity": "medium", "weight": 14},
    "money_transfer_request": {"label": "Money transfer request", "severity": "high", "weight": 22},
    "urgency": {"label": "Urgency", "severity": "medium", "weight": 12},
    "account_blocking_threat": {"label": "Account blocking threat", "severity": "high", "weight": 24},
    "kyc_request": {"label": "KYC request", "severity": "high", "weight": 20},
    "bank_impersonation": {"label": "Bank impersonation", "severity": "high", "weight": 20},
    "brand_sender_domain_mismatch": {"label": "Brand claim and sender domain do not match", "severity": "high", "weight": 24},
    "brand_action_link_mismatch": {"label": "Brand claim and account-action link do not match", "severity": "very_high", "weight": 30},
    "credential_link_action": {"label": "Password or account action requested through a link", "severity": "high", "weight": 22},
    "government_impersonation": {"label": "Government impersonation", "severity": "high", "weight": 20},
    "police_impersonation": {"label": "Police impersonation", "severity": "high", "weight": 22},
    "job_registration_fee": {"label": "Job registration fee", "severity": "high", "weight": 24},
    "job_security_deposit": {"label": "Job security deposit", "severity": "high", "weight": 26},
    "guaranteed_investment_returns": {
        "label": "Guaranteed investment returns",
        "severity": "high",
        "weight": 28,
    },
    "prize_lottery_claim": {"label": "Prize or lottery claim", "severity": "high", "weight": 24},
    "unexpected_prize_offer": {"label": "Unexpected prize or giveaway", "severity": "high", "weight": 24},
    "qr_scam_call_to_action": {"label": "QR code used to claim or verify", "severity": "high", "weight": 26},
    "brand_prize_impersonation": {"label": "Possible brand giveaway impersonation", "severity": "high", "weight": 18},
    "undecodable_qr_with_scam_language": {"label": "Undecodable QR with scam language", "severity": "medium", "weight": 10},
    "refund_scam": {"label": "Refund scam", "severity": "medium", "weight": 18},
    "suspicious_url": {"label": "Suspicious URL", "severity": "medium", "weight": 18},
    "ip_based_url": {"label": "IP-based URL", "severity": "high", "weight": 24},
    "url_shortener": {"label": "URL shortener", "severity": "medium", "weight": 16},
    "suspicious_domain": {"label": "Suspicious domain", "severity": "medium", "weight": 18},
    "live_url_domain_redirect": {"label": "URL redirects to another domain", "severity": "high", "weight": 24},
    "live_url_redirect_chain": {"label": "Long redirect chain", "severity": "medium", "weight": 14},
    "live_page_credential_form": {"label": "Landing page asks for a password", "severity": "very_high", "weight": 30},
    "live_page_sensitive_data_request": {"label": "Landing page asks for sensitive information", "severity": "very_high", "weight": 30},
    "live_page_account_action_form": {"label": "Landing page contains an account-action form", "severity": "high", "weight": 22},
    "live_page_brand_mismatch": {"label": "Landing page brand does not match domain", "severity": "very_high", "weight": 30},
    "unknown_upi_id": {"label": "Unknown-looking UPI ID", "severity": "medium", "weight": 14},
    "qr_payment_request": {"label": "QR payment request", "severity": "high", "weight": 22},
    "sensitive_personal_info_request": {
        "label": "Sensitive personal information request",
        "severity": "high",
        "weight": 22,
    },
}


RISK_LEVELS = (
    (25, "LOW"),
    (50, "MEDIUM"),
    (75, "HIGH"),
    (100, "VERY HIGH"),
)


URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "s.id",
    "rb.gy",
}


SENSITIVE_INFO_TERMS = {
    "aadhaar",
    "aadhar",
    "pan card",
    "pan number",
    "card number",
    "cvv",
    "debit card",
    "credit card",
    "net banking",
    "date of birth",
}


def rule_for(indicator_id: str) -> dict[str, Any]:
    """Return indicator metadata, falling back to a neutral unknown rule."""
    return INDICATOR_RULES.get(
        indicator_id,
        {"label": indicator_id.replace("_", " ").title(), "severity": "low", "weight": 5},
    )
