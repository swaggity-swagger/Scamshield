"""Sender and destination-domain checks for OCR-extracted emails."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .rules import rule_for


# This is an allow-list of official domains for brands that commonly appear in
# phishing lures.  A brand mention alone is never suspicious; the mismatch
# between that claim and a sender/action domain is what produces an indicator.
BRAND_DOMAINS: dict[str, set[str]] = {
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "apple": {"apple.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com"},
    "paypal": {"paypal.com"},
    "state bank of india": {"sbi.co.in", "onlinesbi.sbi"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
}

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
ACTION_RE = re.compile(r"\b(?:reset|change|confirm|verify|unlock|secure|sign[ -]?in|log[ -]?in)\b.{0,50}\b(?:password|account|identity|login)\b|\b(?:password|account|identity|login)\b.{0,50}\b(?:reset|change|confirm|verify|unlock|secure)\b", re.IGNORECASE)


def _indicator(indicator_id: str, evidence: str) -> dict[str, Any]:
    rule = rule_for(indicator_id)
    return {"id": indicator_id, "label": rule["label"], "severity": rule["severity"], "evidence": evidence}


def _domain_for_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower().strip(".")


def _is_official(domain: str, allowed_domains: set[str]) -> bool:
    return any(domain == official or domain.endswith(f".{official}") for official in allowed_domains)


def analyze_email_context(text: str | None, urls: list[str]) -> dict[str, Any]:
    """Identify claimed brands and flag sender/action links outside their domains."""
    content = text or ""
    lowered = content.lower()
    sender_match = re.search(r"\bfrom\s*:\s*[^\n<]*<?([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", content, re.IGNORECASE)
    sender_email = sender_match.group(1) if sender_match else None
    sender_domain = sender_email.rsplit("@", 1)[1].lower() if sender_email else None
    link_domains = list(dict.fromkeys(domain for domain in (_domain_for_url(url) for url in urls) if domain))
    claimed_brands = [brand for brand in BRAND_DOMAINS if re.search(rf"\b{re.escape(brand)}\b", lowered)]
    indicators: list[dict[str, Any]] = []

    for brand in claimed_brands:
        official_domains = BRAND_DOMAINS[brand]
        if sender_domain and not _is_official(sender_domain, official_domains):
            indicators.append(_indicator("brand_sender_domain_mismatch", f"Claims {brand.title()} but sender uses {sender_domain}"))
        for domain in link_domains:
            if not _is_official(domain, official_domains):
                indicators.append(_indicator("brand_action_link_mismatch", f"Claims {brand.title()} but account-action link uses {domain}"))
                break

    if indicators and ACTION_RE.search(content):
        indicators.append(_indicator("credential_link_action", ACTION_RE.search(content).group(0)))

    return {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "claimed_brands": [brand.title() for brand in claimed_brands],
        "link_domains": link_domains,
        "indicators": indicators,
    }
