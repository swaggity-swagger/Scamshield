from typing import Literal

from pydantic import BaseModel


class UnifiedAnalyzeRequest(BaseModel):
    input_type: Literal[
        "text",
        "url",
    ]

    value: str

    preferred_language: Literal[
        "en",
        "hi",
        "mr",
    ] = "en"