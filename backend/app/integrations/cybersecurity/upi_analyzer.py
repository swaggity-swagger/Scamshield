"""UPI and UPI QR payload analysis."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlparse

from .risk_engine import calculate_risk
from .rules import rule_for


UPI_ID_RE = re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}[a-zA-Z0-9]*\b")


def _indicator(indicator_id: str, evidence: str) -> dict[str, Any]:
    rule = rule_for(indicator_id)
    return {
        "id": indicator_id,
        "label": rule["label"],
        "severity": rule["severity"],
        "evidence": evidence,
    }


def _first(qs: dict[str, list[str]], key: str) -> str | None:
    values = qs.get(key)
    return unquote_plus(values[0]) if values else None


def _unknown_looking_upi(upi_id: str) -> bool:
    local, _, handle = upi_id.partition("@")
    long_digit_run = bool(re.search(r"\d{6,}", local))
    randomish = len(local) >= 14 and bool(re.search(r"\d", local)) and bool(re.search(r"[._-]", local))
    uncommon_handle = handle.lower() not in {
        "upi",
        "okaxis",
        "okhdfcbank",
        "okicici",
        "oksbi",
        "ybl",
        "ibl",
        "axl",
        "paytm",
        "apl",
    }
    return long_digit_run or randomish or uncommon_handle


def analyze_upi(data: str | dict[str, Any] | None, context_text: str | None = None) -> dict[str, Any]:
    """Extract and analyze UPI payment information from supplied content."""
    indicators: list[dict[str, Any]] = []
    parsed_fields: dict[str, Any] = {}
    raw = ""

    if isinstance(data, dict):
        parsed_fields = {k: v for k, v in data.items() if v is not None}
        raw = " ".join(str(value) for value in parsed_fields.values())
    elif data:
        raw = str(data)
        parsed = urlparse(raw)
        if parsed.scheme.lower() == "upi":
            qs = parse_qs(parsed.query)
            parsed_fields = {
                "upi_id": _first(qs, "pa"),
                "payee_name": _first(qs, "pn"),
                "amount": _first(qs, "am"),
                "transaction_note": _first(qs, "tn"),
                "currency": _first(qs, "cu"),
            }
            parsed_fields = {k: v for k, v in parsed_fields.items() if v}
        else:
            match = UPI_ID_RE.search(raw)
            if match:
                parsed_fields["upi_id"] = match.group(0)

    context_parts = [context_text or ""]
    if parsed_fields.get("transaction_note"):
        context_parts.append(str(parsed_fields["transaction_note"]))
    context = " ".join(context_parts).strip()
    upi_id = str(parsed_fields.get("upi_id") or parsed_fields.get("pa") or "")
    amount_value = parsed_fields.get("amount") or parsed_fields.get("am")

    if upi_id and _unknown_looking_upi(upi_id):
        indicators.append(_indicator("unknown_upi_id", upi_id))
    if amount_value is not None:
        try:
            amount = float(str(amount_value).replace(",", ""))
            parsed_fields["amount"] = amount
            if amount >= 10000:
                indicators.append(_indicator("payment_request", f"Large UPI amount: {amount:g}"))
        except ValueError:
            indicators.append(_indicator("payment_request", f"Unclear UPI amount: {amount_value}"))
    if re.search(r"\b(?:pay|approve|collect|request|mandate|debit|send)\b", context, flags=re.IGNORECASE):
        indicators.append(_indicator("payment_request", "UPI payment or approval request"))
    if re.search(r"\bqr\b.{0,60}\b(?:pay|approve|scan|payment)\b|\bscan\b.{0,60}\bqr\b", context, flags=re.IGNORECASE):
        indicators.append(_indicator("qr_payment_request", "QR-based payment request"))
    if re.search(r"\bscan\b.{0,50}\b(?:receive|refund|get|collect)\b.{0,30}\b(?:money|cash|refund|amount)\b", context, flags=re.IGNORECASE):
        indicators.append(_indicator("refund_scam", "Message suggests scanning QR to receive money"))
    if re.search(r"\b(?:urgent|immediately|today|now|within\s+\d+\s*(?:minutes?|hours?))\b", context, flags=re.IGNORECASE):
        indicators.append(_indicator("urgency", "Urgency around UPI payment"))

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in indicators:
        if item["id"] not in seen:
            deduped.append(item)
            seen.add(item["id"])

    risk = calculate_risk(deduped)
    return {
        "raw": data,
        "fields": parsed_fields,
        "indicators": deduped,
        **risk,
    }
