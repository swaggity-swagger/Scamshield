"""URL analysis for provided URLs only."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from .risk_engine import calculate_risk
from .rules import URL_SHORTENER_DOMAINS, rule_for


SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "tk", "ml", "ga", "cf", "gq"}
SUSPICIOUS_URL_KEYWORDS = {"verify", "secure", "update", "wallet", "bonus", "claim", "kyc"}
BRAND_LOOKALIKE_HINTS = {
    "paytm",
    "phonepe",
    "googlepay",
    "sbi",
    "hdfc",
    "icici",
    "axisbank",
    "amazon",
    "flipkart",
}


def _indicator(indicator_id: str, evidence: str) -> dict[str, Any]:
    rule = rule_for(indicator_id)
    return {
        "id": indicator_id,
        "label": rule["label"],
        "severity": rule["severity"],
        "evidence": evidence,
    }


def _with_scheme(url: str) -> str:
    if re.match(r"^[a-z][a-z0-9+.-]*://", url, flags=re.IGNORECASE):
        return url
    return f"http://{url}"


def _hostname_parts(hostname: str) -> tuple[str, str]:
    parts = hostname.lower().strip(".").split(".")
    if len(parts) < 2:
        return hostname.lower(), ""
    return ".".join(parts[-2:]), parts[-1]


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_url(url: str) -> dict[str, Any]:
    """Analyze a supplied URL without visiting or scraping it."""
    raw_url = (url or "").strip()
    indicators: list[dict[str, Any]] = []
    if not raw_url:
        return {"url": url, "indicators": [], "risk_score": 0, "risk_level": "LOW"}

    parsed = urlparse(_with_scheme(raw_url))
    hostname = (parsed.hostname or "").lower()
    registered_domain, tld = _hostname_parts(hostname)

    if parsed.scheme == "http":
        indicators.append(_indicator("suspicious_url", "URL uses HTTP instead of HTTPS"))
    if hostname and _is_ip(hostname):
        indicators.append(_indicator("ip_based_url", hostname))
    if len(raw_url) > 120:
        indicators.append(_indicator("suspicious_url", "Unusually long URL"))
    if re.search(r"[@\\]|%00|%2f|%5c", raw_url, flags=re.IGNORECASE):
        indicators.append(_indicator("suspicious_url", "Suspicious URL characters or encoding"))
    if parsed.username or parsed.password:
        indicators.append(_indicator("suspicious_url", "Username or password embedded in URL"))
    if parsed.port and parsed.port not in {80, 443}:
        indicators.append(_indicator("suspicious_url", f"Suspicious port: {parsed.port}"))
    if hostname.count(".") >= 3 and not _is_ip(hostname):
        indicators.append(_indicator("suspicious_domain", "Excessive subdomains"))
    if registered_domain in URL_SHORTENER_DOMAINS:
        indicators.append(_indicator("url_shortener", registered_domain))
    if hostname.startswith("xn--") or ".xn--" in hostname:
        indicators.append(_indicator("suspicious_domain", "Punycode domain may hide lookalike characters"))
    if tld in SUSPICIOUS_TLDS:
        indicators.append(_indicator("suspicious_domain", f"Risky or unusual TLD: .{tld}"))

    compact_host = re.sub(r"[^a-z0-9]", "", hostname)
    for brand in BRAND_LOOKALIKE_HINTS:
        if brand in compact_host and registered_domain.replace(".", "") != brand:
            indicators.append(_indicator("suspicious_domain", f"Possible brand lookalike: {hostname}"))
            break

    keyword_hits = sorted(keyword for keyword in SUSPICIOUS_URL_KEYWORDS if keyword in raw_url.lower())
    if len(keyword_hits) >= 2:
        indicators.append(_indicator("suspicious_url", f"Multiple sensitive URL terms: {', '.join(keyword_hits)}"))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in indicators:
        key = (item["id"], item["evidence"])
        if key not in seen:
            deduped.append(item)
            seen.add(key)

    risk = calculate_risk(deduped)
    return {
        "url": raw_url,
        "scheme": parsed.scheme,
        "domain": hostname,
        "indicators": deduped,
        **risk,
    }
