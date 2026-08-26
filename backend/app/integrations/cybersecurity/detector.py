"""Text indicator detection for ScamShield."""

from __future__ import annotations

import re
from typing import Any

from .rules import SENSITIVE_INFO_TERMS, rule_for


PatternSpec = tuple[str, list[str]]


PATTERNS: list[PatternSpec] = [
    ("otp_request", [r"\b(?:share|send|tell|provide|enter|verify|give)\b.{0,30}\botp\b", r"\botp\b.{0,30}\b(?:share|send|provide|enter|verify)\b", r"\b(?:share|send|tell|provide|enter|give)\b.{0,45}\b(?:six|6)[-\s]?(?:digit|digits|number)\b.{0,35}\b(?:code|bank code|verification)\b", r"\b(?:six|6)[-\s]?(?:digit|digits|number)\b.{0,35}\b(?:bank\s+)?(?:code|verification)\b.{0,45}\b(?:share|send|tell|provide|enter|give)\b"]),
    ("pin_request", [r"\b(?:upi|atm|card|bank|account)?\s*pin\b.{0,30}\b(?:share|send|enter|provide|verify)\b", r"\b(?:share|send|enter|provide|verify)\b.{0,30}\b(?:upi\s*)?pin\b"]),
    ("password_request", [r"\b(?:share|send|provide|enter|verify|confirm)\b.{0,30}\bpassword\b", r"\bpassword\b.{0,30}\b(?:share|send|provide|enter|verify)\b"]),
    ("payment_request", [r"\b(?:pay|payment|fee|charges?|deposit|transfer)\b.{0,20}(?:rs\.?|inr|Γé╣|\d)", r"(?:rs\.?|inr|Γé╣)\s?\d+.{0,25}\b(?:pay|payment|fee|deposit|charges?)\b"]),
    ("money_transfer_request", [r"\b(?:transfer|send)\b.{0,30}\b(?:money|amount|funds?|cash|Γé╣|rs\.?|inr)\b", r"\b(?:bank transfer|wire transfer|upi transfer)\b"]),
    ("urgency", [r"\b(?:urgent|immediately|within\s+\d+\s*(?:minutes?|hours?|days?)|now|last chance|final notice|limited time|act fast)\b", r"\btoday\b.{0,45}\b(?:pay|verify|complete|block|blocked|suspend|fine|claim|transfer|confirm)\b", r"\b(?:pay|verify|complete|block|blocked|suspend|fine|claim|transfer|confirm)\b.{0,45}\btoday\b"]),
    ("account_blocking_threat", [r"\b(?:account|card|wallet|upi|netbanking)\b.{0,40}\b(?:block|blocked|suspend|suspended|freeze|frozen|deactivate|closed|stop|stopped)\b", r"\b(?:block|suspend|freeze|deactivate|stop)\b.{0,30}\b(?:account|card|wallet|upi)\b"]),
    ("kyc_request", [r"\b(?:complete|update|verify|renew)\b.{0,20}\bkyc\b", r"\bkyc\b.{0,30}\b(?:complete|update|verify|pending|expired)\b"]),
    ("bank_impersonation", [r"\b(?:sbi|hdfc|icici|axis|kotak|yes bank|rbi)\b.{0,50}\b(?:alert|notice|verification|department|customer care|official)\b", r"\b(?:bank|rbi)\b.{0,30}\b(?:kyc|blocked|suspended|verification department|customer care)\b"]),
    ("government_impersonation", [r"\b(?:government|govt|income tax|tax department|uidai|aadhaar|rbi|passport seva)\b.{0,50}\b(?:notice|department|official|verification|fine)\b"]),
    ("police_impersonation", [r"\b(?:police|cyber crime|crime branch|cbi|enforcement|ed officer)\b.{0,50}\b(?:case|warrant|notice|arrest|fine|investigation)\b"]),
    ("job_registration_fee", [r"\b(?:job|work from home|interview|selected|offer)\b.{0,80}\b(?:registration|processing|application)\s+fee\b"]),
    ("job_security_deposit", [r"\b(?:job|work from home|selected|offer)\b.{0,80}\b(?:security|refundable)\s+deposit\b"]),
    ("guaranteed_investment_returns", [r"\bguaranteed\b.{0,35}\b(?:return|profit|income|earnings?)\b", r"\b(?:double|triple)\b.{0,25}\b(?:money|investment)\b", r"\b\d{2,3}%\b.{0,25}\b(?:return|profit)\b"]),
    ("prize_lottery_claim", [r"\b(?:congratulations|congrats|winner|won|selected)\b.{0,50}\b(?:prize|lottery|lucky draw|reward|cashback|gift)\b", r"\bclaim\b.{0,25}\b(?:prize|lottery|reward|gift)\b"]),
    ("unexpected_prize_offer", [r"\b(?:congratulations|congrats|you(?:'| a)?ve won|winner|lucky winner|selected)\b.{0,70}\b(?:iphone|phone|smartphone|voucher|gift(?:\s*card)?|reward|prize|giveaway|cash)\b", r"\b(?:free|win|won)\b.{0,35}\b(?:iphone|phone|smartphone|voucher|gift(?:\s*card)?|reward|prize)\b"]),
    ("brand_prize_impersonation", [r"\b(?:apple|amazon|google|microsoft|flipkart|paytm|phonepe)\b.{0,80}\b(?:winner|won|prize|reward|gift|giveaway|free|claim)\b", r"\b(?:winner|won|prize|reward|gift|giveaway|free|claim)\b.{0,80}\b(?:apple|amazon|google|microsoft|flipkart|paytm|phonepe)\b"]),
    ("refund_scam", [r"\b(?:refund|cashback|reversal)\b.{0,50}\b(?:claim|process|receive|approve|scan|upi)\b"]),
    ("sensitive_personal_info_request", [rf"\b(?:share|send|provide|enter|verify|submit|upload)\b.{{0,40}}\b(?:{'|'.join(re.escape(term) for term in SENSITIVE_INFO_TERMS)})\b"]),
]


def _normalize(text: str | None) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _make_indicator(indicator_id: str, evidence: str) -> dict[str, Any]:
    rule = rule_for(indicator_id)
    return {
        "id": indicator_id,
        "label": rule["label"],
        "severity": rule["severity"],
        "evidence": evidence.strip(),
    }


def detect_indicators(text: str | None, *, qr_detected: bool = False, qr_decoded: bool = False) -> list[dict[str, Any]]:
    """Detect scam indicators in provided text using bounded regex patterns.

    The detector avoids unlimited keyword counting by returning each indicator
    only once with the first useful evidence phrase.
    """
    normalized = _normalize(text)
    if not normalized:
        return []

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for indicator_id, patterns in PATTERNS:
        for pattern in patterns:
            match = re.search(pattern, normalized, flags=re.IGNORECASE)
            if match and indicator_id not in seen:
                results.append(_make_indicator(indicator_id, match.group(0)))
                seen.add(indicator_id)
                break

    lowered = normalized.lower()
    # A QR code alone (including a menu or Wi-Fi QR) is neutral.  Treat it as
    # payment-related only when payment/collection language is also present.
    if "qr" in lowered and re.search(r"\b(?:pay|payment|upi|receive money|collect)\b", lowered):
        if "qr_payment_request" not in seen:
            evidence = re.search(r".{0,25}\bqr\b.{0,45}", normalized, flags=re.IGNORECASE)
            results.append(_make_indicator("qr_payment_request", evidence.group(0) if evidence else "QR payment request"))

    scam_lure_ids = {"prize_lottery_claim", "unexpected_prize_offer", "urgency", "account_blocking_threat", "kyc_request", "sensitive_personal_info_request"}
    has_scam_lure = bool(seen & scam_lure_ids)
    qr_action = re.search(r"\b(?:scan(?:\s+(?:the\s+)?)?(?:qr|code)|claim|verify|confirm|enter\s+details)\b", normalized, flags=re.IGNORECASE)
    if qr_detected and has_scam_lure and qr_action and "qr_scam_call_to_action" not in seen:
        results.append(_make_indicator("qr_scam_call_to_action", qr_action.group(0)))
        seen.add("qr_scam_call_to_action")
    if qr_detected and not qr_decoded and has_scam_lure and "undecodable_qr_with_scam_language" not in seen:
        results.append(_make_indicator("undecodable_qr_with_scam_language", "QR code detected but its content could not be decoded"))

    return results
