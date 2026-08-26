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
    extract_chat_risk_context,
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


# ============================================================
# CREATE CONVERSATION
# ============================================================

@router.post(
    "/conversations",
    response_model=ChatConversationResponse,
)
def create_chat_conversation(
    data: ChatConversationCreate,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Create a new chatbot conversation.
    """

    return create_conversation(
        db,
        current_user.id,
        data.title,
        data.language,
    )


# ============================================================
# LIST CONVERSATIONS
# ============================================================

@router.get(
    "/conversations",
    response_model=list[ChatConversationResponse],
)
def get_chat_conversations(
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Return all conversations belonging to
    the authenticated user.
    """

    return list_conversations(
        db,
        current_user.id,
    )


# ============================================================
# CHANGE CONVERSATION LANGUAGE
# ============================================================

@router.patch(
    "/conversations/{conversation_id}/language",
    response_model=ChatConversationResponse,
)
def change_language(
    conversation_id: int,
    data: ChatLanguageUpdate,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Change the language of a conversation.
    """

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


# ============================================================
# GET CONVERSATION + MESSAGES
# ============================================================

@router.get(
    "/conversations/{conversation_id}",
)
def get_chat_conversation(
    conversation_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Return one conversation and its message history.
    """

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


# ============================================================
# DELETE CONVERSATION
# ============================================================

@router.delete(
    "/conversations/{conversation_id}",
)
def remove_chat_conversation(
    conversation_id: int,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Delete a conversation belonging to the
    authenticated user.
    """

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


# ============================================================
# SEND CHAT MESSAGE
# ============================================================

@router.post(
    "/message",
    response_model=ChatMessageResponse,
)
def send_chat_message(
    conversation_id: int,
    data: ChatMessageRequest,
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Send a user message to the ScamShield assistant.

    When an incident_id is supplied, the assistant receives
    the authenticated user's incident context, including:

        - incident details
        - latest analysis
        - analysis history
        - evidence
        - threat findings
        - timeline
        - recommended actions
    """

    # ---------------------------------------------------------
    # Verify conversation ownership
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Get recent conversation history
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Build incident context
    # ---------------------------------------------------------

    incident_context = None
    risk_context = None
    suggested_actions: list[str] = []

    if data.incident_id is not None:

        incident_context = build_incident_context(
            db=db,
            incident_id=data.incident_id,
            user_id=current_user.id,
        )

        # Prevent access to another user's incident.
        if incident_context is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        (
            risk_context,
            suggested_actions,
        ) = extract_chat_risk_context(
            incident_context
        )

    # ---------------------------------------------------------
    # Save user message
    # ---------------------------------------------------------

    save_message(
        db,
        conversation_id,
        "user",
        data.message,
    )

    # ---------------------------------------------------------
    # Generate AI response
    # ---------------------------------------------------------

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
        ) from exc

    # ---------------------------------------------------------
    # Save assistant response
    # ---------------------------------------------------------

    save_message(
        db,
        conversation_id,
        "assistant",
        reply,
    )

    # ---------------------------------------------------------
    # Return complete chatbot response
    # ---------------------------------------------------------

    return ChatMessageResponse(
        conversation_id=conversation_id,
        reply=reply,
        language=conversation.language,
        incident_id=data.incident_id,
        risk_context=risk_context,
        suggested_actions=suggested_actions,
    )