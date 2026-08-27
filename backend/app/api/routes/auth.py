from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.database.session import get_db
from app.schemas.auth import RegisterRequest
from app.services.auth_service import create_user, get_user_by_email


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post("/register")
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
):
    existing_user = get_user_by_email(db, data.email)

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Email is already registered.",
        )

    user = create_user(
        db=db,
        name=data.name,
        email=data.email,
        password=data.password,
    )

    return {
        "message": "User registered successfully.",
        "user_id": user.id,
    }