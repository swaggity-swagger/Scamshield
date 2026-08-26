from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.services.dashboard_service import (
    get_dashboard_summary,
)


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary")
def dashboard_summary(
    current_user: User = Depends(
        get_current_user
    ),
    db: Session = Depends(get_db),
):
    """
    Return dashboard statistics for the
    authenticated user.
    """

    return get_dashboard_summary(
        db=db,
        user_id=current_user.id,
    )