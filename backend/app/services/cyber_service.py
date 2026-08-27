"""Thin wrapper around the member5 cybersecurity module.

We keep the original analysis logic untouched – this file simply imports
``member5.cybersecurity.analyzer.analyze_input`` and exposes a convenient
function ``cyber_analyze`` that matches the signature expected by the new
orchestration endpoint.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

# Import the canonical analyser from the top‑level ``member5`` package.
# The repository root has been added to ``sys.path`` in ``app/__init__.py``.
from member5.cybersecurity.analyzer import analyze_input as _member5_analyze_input


def cyber_analyze(
    text: Optional[str] = None,
    urls: Optional[list[str] | str] = None,
    qr_data: Optional[list[str] | str] = None,
    upi_data: Optional[dict[str, Any] | str] = None,
    qr_detected: bool = False,
) -> dict:
    """Run the member5 cybersecurity analysis.

    Parameters are forwarded directly to ``member5.cybersecurity.analyzer``.
    ``qr_detected`` is a convenience flag – the original function expects it.
    """
    return _member5_analyze_input(
        text=text,
        urls=urls,
        qr_data=qr_data,
        upi_data=upi_data,
        qr_detected=qr_detected,
    )
