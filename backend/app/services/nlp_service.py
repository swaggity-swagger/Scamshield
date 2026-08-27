"""Thin wrapper around the canonical member3 NLP module.

We keep the original logic untouched – this file merely imports the public
function ``member3.analyzer.analyze_text`` and exposes it with the same
signature that the rest of the backend expects.  By using a wrapper we avoid
modifying any code inside ``member3`` and we can swap the implementation in
the future without touching the rest of the service layer.
"""

from __future__ import annotations

from typing import Literal

# Import the *canonical* NLP analyser from the top‑level ``member3`` package.
# The repository root is added to ``sys.path`` in ``app/__init__.py``.
from member3.analyzer import analyze_text as _member3_analyze_text


def nlp_analyze(
    text: str,
    preferred_language: Literal["en", "hi", "mr"] = "en",
) -> dict:
    """Run the member3 NLP analyser.

    Parameters
    ----------
    text:
        The raw message (or OCR‑extracted text) to analyse.
    preferred_language:
        Language code – defaults to English.  The underlying analyser
        supports ``"en"``, ``"hi"`` and ``"mr"``.

    Returns
    -------
    dict
        The dictionary produced by ``member3.analyzer.analyze_text`` – it
        contains ``risk_score``, ``risk_level``, ``confidence`` and a list of
        ``evidence`` objects.
    """
    return _member3_analyze_text(text, preferred_language=preferred_language)
