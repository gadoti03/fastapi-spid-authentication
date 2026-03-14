# routers/login.py
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.requests import Request
from fastapi.responses import Response, JSONResponse

from sqlalchemy.orm import Session
from database.connection import get_db

from services.session_service import get_or_create_session_by_session_id, get_id_user_by_session_id

from repositories.user_repository import UserRepository

router = APIRouter()

@router.get("/login", response_class=Response)
async def login(request: Request, db: Session = Depends(get_db)):

    session_id = request.cookies.get("session_id")

    db_session = get_or_create_session_by_session_id(db, session_id)

    response = Response(content='{"msg": "session created"}', media_type="application/json")
    
    # set cookie properly
    response.set_cookie(
        key="session_id",
        value=db_session.session_id,
        httponly=True,
        secure=True,
        samesite="none",
        path="/"
    )

    return response

@router.get("/me")
async def me(request: Request, db: Session = Depends(get_db)):

    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user_id = get_id_user_by_session_id(db, session_id)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = UserRepository.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return JSONResponse(
        content={
            "id": user.id,
            "cf": user.cf,
            "created": user.created_at.isoformat(),
            "updated": user.updated_at.isoformat()
        }
    )