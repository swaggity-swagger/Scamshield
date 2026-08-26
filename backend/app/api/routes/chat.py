from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User

from app.schemas.chat import (
    ChatConversationCreate,
    ChatConversationResponse,
    ChatLanguageUpdate,
    ChatMessageRequest,
    ChatMessageResponse,
)

from app.services.chat_ai import (
    generate_chat_response,
)

from app.services.chat_context import (
    build_incident_context,
)

from app.services.chat_service import (
    create_conversation,
    delete_conversation,
    get_conversation,
    get_messages,
    list_conversations,
    save_message,
    update_language,
)


router = APIRouter(
    prefix="/api/v1/chat",
    tags=["Chat Assistant"],
)


@router.post(
    "/conversations",
    response_model=ChatConversationResponse,
)
def create_chat_conversation(
    data: ChatConversationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return create_conversation(
        db,
        current_user.id,
        data.title,
        data.language,
    )


@router.get(
    "/conversations",
    response_model=list[ChatConversationResponse],
)
def get_chat_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return list_conversations(
        db,
        current_user.id,
    )


@router.patch(
    "/conversations/{conversation_id}/language",
    response_model=ChatConversationResponse,
)
def change_language(
    conversation_id: int,
    data: ChatLanguageUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conversation = update_language(
        db,
        conversation_id,
        current_user.id,
        data.language,
    )

    if conversation is None:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found.",
        )

    return conversation


@router.get(
    "/conversations/{conversation_id}",
)
def get_chat_conversation(
    conversation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conversation = get_conversation(
        db,
        conversation_id,
        current_user.id,
    )

    if conversation is None:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found.",
        )

    messages = get_messages(
        db,
        conversation_id,
    )

    return {
        "id": conversation.id,
        "title": conversation.title,
        "language": conversation.language,
        "created_at": conversation.created_at,
        "updated_at": conversation.updated_at,
        "messages": [
            {
                "id": item.id,
                "role": item.role,
                "content": item.content,
                "created_at": item.created_at,
            }
            for item in messages
        ],
    }


@router.delete(
    "/conversations/{conversation_id}",
)
def remove_chat_conversation(
    conversation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    deleted = delete_conversation(
        db,
        conversation_id,
        current_user.id,
    )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found.",
        )

    return {
        "message": "Conversation deleted."
    }


@router.post(
    "/message",
    response_model=ChatMessageResponse,
)
def send_chat_message(
    conversation_id: int,
    data: ChatMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conversation = get_conversation(
        db,
        conversation_id,
        current_user.id,
    )

    if conversation is None:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found.",
        )

    messages = get_messages(
        db,
        conversation_id,
    )

    history = [
        {
            "role": item.role,
            "content": item.content,
        }
        for item in messages[-20:]
        if item.role in {
            "user",
            "assistant",
        }
    ]

    incident_context = None

    if data.incident_id is not None:
        incident_context = build_incident_context(
            db,
            data.incident_id,
            current_user.id,
        )

        if incident_context is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

    save_message(
        db,
        conversation_id,
        "user",
        data.message,
    )

    try:
        reply = generate_chat_response(
            message=data.message,
            conversation_history=history,
            language=conversation.language,
            incident_context=incident_context,
        )

    except Exception as exc:
        print(
            f"Chat assistant error: {exc}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "The AI assistant is temporarily "
                "unavailable. Please try again."
            ),
        )

    save_message(
        db,
        conversation_id,
        "assistant",
        reply,
    )

    return ChatMessageResponse(
        conversation_id=conversation_id,
        reply=reply,
        language=conversation.language,
        incident_id=data.incident_id,
    )