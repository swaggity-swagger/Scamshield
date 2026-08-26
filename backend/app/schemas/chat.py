from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ChatLanguage = Literal[
    "en",
    "hi",
    "mr",
]


class ChatConversationCreate(BaseModel):
    title: str | None = Field(
        default=None,
        max_length=200,
    )

    language: ChatLanguage = "en"


class ChatConversationResponse(BaseModel):
    id: int
    title: str | None
    language: ChatLanguage
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


class ChatLanguageUpdate(BaseModel):
    language: ChatLanguage


class ChatMessageRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=4000,
    )

    incident_id: int | None = None


class ChatMessageResponse(BaseModel):
    conversation_id: int
    reply: str
    language: ChatLanguage
    incident_id: int | None = None
    risk_context: str | None = None
    suggested_actions: list[str] = []