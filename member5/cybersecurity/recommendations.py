"""Simple user-safe recommendations for ScamShield findings."""

from __future__ import annotations

from typing import Any


DEFAULT_RECOMMENDATIONS = {
    "OTP_SCAM": "Do not share your OTP or UPI PIN with anyone.",
    "PHISHING": "Do not click the link. Open the official website or app manually.",
    "SMISHING": "Do not reply to the message or open links from it.",
    "UPI_SCAM": "Do not approve an unexpected UPI payment request.",
    "QR_SCAM": "Do not scan a QR code to receive money.",
    "JOB_SCAM": "Do not pay registration or security fees for an unsolicited job offer.",
    "INVESTMENT_SCAM": "Do not transfer money based only on guaranteed-return claims.",
    "IMPERSONATION": "Verify the identity using an official contact channel.",
    "PAYMENT_SCAM": "Pause before paying and confirm the request through a trusted channel.",
    "PRIZE_SCAM": "Do not pay any fee to claim a prize or lottery.",
    "REFUND_SCAM": "Do not scan QR codes or enter UPI PINs to receive a refund.",
    "NORMAL_OR_UNKNOWN": "No strong scam signs were found, but stay cautious with links and payment requests.",
}

INDICATOR_RECOMMENDATIONS = {
    "otp_request": "Do not share your OTP.",
    "pin_request": "Do not enter or share your UPI PIN unless you started the payment yourself.",
    "password_request": "Do not share your password.",
    "account_blocking_threat": "Contact the bank or service through its official app, website, or phone number.",
    "kyc_request": "Update KYC only through the official app, branch, or verified website.",
    "suspicious_url": "Avoid opening suspicious links from messages.",
    "url_shortener": "Be careful with shortened links because the real destination is hidden.",
    "ip_based_url": "Avoid links that use an IP address instead of a normal website name.",
    "unknown_upi_id": "Do not pay an unfamiliar UPI ID unless you can verify the recipient.",
    "sensitive_personal_info_request": "Do not send Aadhaar, PAN, card, CVV, or personal details over chat.",
}


def generate_recommendations(scam_type: str, indicators: list[dict[str, Any]]) -> list[str]:
    """Generate short, low-technical-skill recommendations."""
    recommendations = [DEFAULT_RECOMMENDATIONS.get(scam_type, DEFAULT_RECOMMENDATIONS["NORMAL_OR_UNKNOWN"])]
    for item in indicators:
        message = INDICATOR_RECOMMENDATIONS.get(str(item.get("id")))
        if message and message not in recommendations:
            recommendations.append(message)
    if scam_type != "NORMAL_OR_UNKNOWN":
        final = "If money or personal information may already have been shared, contact the bank or service provider immediately."
        if final not in recommendations:
            recommendations.append(final)
    return recommendations[:5]
