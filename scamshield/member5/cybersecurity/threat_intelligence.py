"""Threat-intelligence integration boundary for ScamShield.

This module intentionally does not call any external services yet. It provides
a stable shape for future integrations such as phishing feeds, malicious URL
databases, and domain reputation APIs.
"""

from __future__ import annotations

from typing import Any


def check_url_reputation(url: str) -> dict[str, Any]:
    """Return URL reputation status from configured threat-intelligence sources.

    No external source is configured in this first version, so the function
    reports that clearly instead of inventing reputation results.
    """
    return {
        "target": url,
        "target_type": "url",
        "source": None,
        "configured": False,
        "status": "not_checked",
        "message": "No external threat-intelligence source is configured.",
        "indicators": [],
    }


def check_domain_reputation(domain: str) -> dict[str, Any]:
    """Return domain reputation status from configured threat-intelligence sources."""
    return {
        "target": domain,
        "target_type": "domain",
        "source": None,
        "configured": False,
        "status": "not_checked",
        "message": "No external threat-intelligence source is configured.",
        "indicators": [],
    }
