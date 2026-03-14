# routers/dashboard.py
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from fastapi.requests import Request

from sqlalchemy.orm import Session
from database.connection import get_db

from repositories.session_repository import SessionRepository

router = APIRouter()

@router.get("/dashboard", response_class=Response) # response_class=Response: avoid default JSON response
async def dashboard(request: Request, db: Session = Depends(get_db)):
        
    # Get session ID from cookies
    session_id = request.cookies.get("session_id")

    # Get existing session or create new one if not valid
    db_session = SessionRepository.get_by_id(db, session_id)

    if not db_session:
        response = Response(content='{"msg": "invalid session"}', media_type="application/json", status_code=401)    
        response.delete_cookie(key="session_id")
        return response

    # Set session cookie in response
    response = Response(content='{"msg": "welcome to dashboard"}', media_type="application/json")
    response.set_cookie(
        key="session_id", 
        value=db_session.session_id,
        httponly=True,
        secure=True,
        samesite="none",
        path="/"
    )
    return response
