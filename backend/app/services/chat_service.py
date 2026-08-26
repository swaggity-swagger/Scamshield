from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.chat_conversation import (
    ChatConversation,
)
from app.models.chat_message import (
    ChatMessage,
)


def create_conversation(
    db: Session,
    user_id: int,
    title: str | None,
    language: str,
):
    conversation = ChatConversation(
        user_id=user_id,
        title=title,
        language=language,
    )

    db.add(conversation)
    db.commit()
    db.refresh(conversation)

    return conversation


def get_conversation(
    db: Session,
    conversation_id: int,
    user_id: int,
):
    statement = select(
        ChatConversation
    ).where(
        ChatConversation.id == conversation_id,
        ChatConversation.user_id == user_id,
    )

    return db.scalar(statement)


def list_conversations(
    db: Session,
    user_id: int,
):
    statement = (
        select(ChatConversation)
        .where(
            ChatConversation.user_id == user_id
        )
        .order_by(
            ChatConversation.updated_at.desc()
        )
    )

    return db.scalars(statement).all()


def get_messages(
    db: Session,
    conversation_id: int,
):
    statement = (
        select(ChatMessage)
        .where(
            ChatMessage.conversation_id
            == conversation_id
        )
        .order_by(
            ChatMessage.created_at.asc()
        )
    )

    return db.scalars(statement).all()


def save_message(
    db: Session,
    conversation_id: int,
    role: str,
    content: str,
):
    message = ChatMessage(
        conversation_id=conversation_id,
        role=role,
        content=content,
    )

    db.add(message)
    db.commit()
    db.refresh(message)

    return message


def update_language(
    db: Session,
    conversation_id: int,
    user_id: int,
    language: str,
):
    conversation = get_conversation(
        db,
        conversation_id,
        user_id,
    )

    if conversation is None:
        return None

    conversation.language = language

    db.commit()
    db.refresh(conversation)

    return conversation


def delete_conversation(
    db: Session,
    conversation_id: int,
    user_id: int,
):
    conversation = get_conversation(
        db,
        conversation_id,
        user_id,
    )

    if conversation is None:
        return False

    db.delete(conversation)
    db.commit()

    return True