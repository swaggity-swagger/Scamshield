"""Safe, bounded live URL inspection for suspicious links."""

from __future__ import annotations

import html
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError

from .rules import rule_for


MAX_REDIRECTS = 5
MAX_BYTES = 256 * 1024
TIMEOUT_SECONDS = 5
USER_AGENT = "ScamShield-SafeURLInspector/1.0"
BRAND_HINTS = {"sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "amazon", "flipkart"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes


def _indicator(indicator_id: str, evidence: str) -> dict[str, Any]:
    rule = rule_for(indicator_id)
    return {
        "id": indicator_id,
        "label": rule["label"],
        "severity": rule["severity"],
        "evidence": evidence,
    }


def _is_private_host(hostname: str) -> bool:
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


def _fetch_once(url: str) -> FetchResult:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"})
    opener = build_opener(_NoRedirect())
    try:
        response = opener.open(request, timeout=TIMEOUT_SECONDS)
        status_code = response.getcode()
        headers = dict(response.headers.items())
        body = response.read(MAX_BYTES + 1)
        return FetchResult(url=response.geturl(), status_code=status_code, headers=headers, body=body[:MAX_BYTES])
    except HTTPError as error:
        body = error.read(MAX_BYTES + 1)
        return FetchResult(url=error.geturl(), status_code=error.code, headers=dict(error.headers.items()), body=body[:MAX_BYTES])


def _decode_html(body: bytes, content_type: str) -> str:
    charset_match = re.search(r"charset=([\w.-]+)", content_type, flags=re.IGNORECASE)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _visible_text(markup: str) -> str:
    without_scripts = re.sub(r"<(?:script|style|noscript)\b[^>]*>.*?</(?:script|style|noscript)>", " ", markup, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", without_scripts)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _title(markup: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", markup, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", html.unescape(match.group(1))).strip() or None


def _registered_domain(hostname: str) -> str:
    parts = hostname.lower().strip(".").split(".")
    if len(parts) < 2:
        return hostname.lower()
    return ".".join(parts[-2:])


def _page_indicators(markup: str, visible_text: str, final_hostname: str) -> list[dict[str, Any]]:
    lowered_markup = markup.lower()
    lowered_text = visible_text.lower()
    indicators: list[dict[str, Any]] = []

    if re.search(r"<input[^>]+type=[\"']?password", lowered_markup):
        indicators.append(_indicator("live_page_credential_form", "Landing page contains a password field"))
    if re.search(r"\b(?:otp|one[-\s]?time password|upi pin|cvv|card number|net banking)\b", lowered_text):
        indicators.append(_indicator("live_page_sensitive_data_request", "Landing page asks for OTP, PIN, card, or banking details"))
    if re.search(r"\b(?:verify|update|complete|login|sign in|kyc|blocked|suspended)\b", lowered_text) and re.search(r"<form\b", lowered_markup):
        indicators.append(_indicator("live_page_account_action_form", "Landing page has an account-action form"))

    compact_host = re.sub(r"[^a-z0-9]", "", final_hostname.lower())
    for brand in BRAND_HINTS:
        if re.search(rf"\b{re.escape(brand)}\b", lowered_text) and brand not in compact_host:
            indicators.append(_indicator("live_page_brand_mismatch", f"Landing page mentions {brand.upper()} on non-{brand.upper()} domain"))
            break

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in indicators:
        key = (item["id"], item["evidence"])
        if key not in seen:
            deduped.append(item)
            seen.add(key)
    return deduped


def inspect_live_url(url: str, *, allow_private_hosts: bool = False) -> dict[str, Any]:
    """Fetch a URL safely enough for prototype risk analysis.

    The inspector does not execute JavaScript, does not send cookies or user
    credentials, refuses private/internal hosts by default, limits redirects,
    and reads only a small response body.
    """
    current_url = url.strip()
    redirects: list[str] = []
    final_result: FetchResult | None = None

    try:
        for _ in range(MAX_REDIRECTS + 1):
            parsed = urlparse(current_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return {"status": "skipped", "reason": "Only http and https URLs can be inspected.", "indicators": []}
            if not allow_private_hosts and _is_private_host(parsed.hostname):
                return {"status": "blocked", "reason": "Private or internal network address was not fetched.", "indicators": []}

            fetched = _fetch_once(current_url)
            final_result = fetched
            if fetched.status_code not in {301, 302, 303, 307, 308}:
                break

            location = fetched.headers.get("Location") or fetched.headers.get("location")
            if not location:
                break
            next_url = urljoin(current_url, location)
            redirects.append(next_url)
            current_url = next_url
        else:
            return {"status": "error", "reason": "Too many redirects.", "indicators": [_indicator("live_url_redirect_chain", "More than five redirects")]}
    except (TimeoutError, URLError, OSError) as error:
        return {"status": "unavailable", "reason": str(error), "indicators": []}

    if final_result is None:
        return {"status": "unavailable", "reason": "No response was received.", "indicators": []}

    final_url = final_result.url
    final_host = (urlparse(final_url).hostname or "").lower()
    original_host = (urlparse(url).hostname or "").lower()
    indicators: list[dict[str, Any]] = []
    if redirects and _registered_domain(original_host) != _registered_domain(final_host):
        indicators.append(_indicator("live_url_domain_redirect", f"Redirects from {original_host} to {final_host}"))

    content_type = final_result.headers.get("Content-Type", "")
    page_title = None
    if "text/html" in content_type.lower() or final_result.body.lstrip().startswith(b"<"):
        markup = _decode_html(final_result.body, content_type)
        text = _visible_text(markup)
        page_title = _title(markup)
        indicators.extend(_page_indicators(markup, text, final_host))

    return {
        "status": "fetched",
        "final_url": final_url,
        "status_code": final_result.status_code,
        "content_type": content_type,
        "redirect_chain": redirects,
        "title": page_title,
        "bytes_read": len(final_result.body),
        "indicators": indicators,
    }
