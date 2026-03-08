from fastapi import APIRouter
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request

from fastapi import Depends
from sqlalchemy.orm import Session
from database.connection import get_db

from database.models import Session as DBSess

from datetime import datetime, timedelta
import uuid

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/login", response_class=Response) # response_class=Response: avoid default JSON response
async def login(request: Request, db: Session = Depends(get_db)):
    
    db_session = None
    
    Session_id = request.cookies.get("session_id")
    
    if Session_id:
        db_session = db.query(DBSess).filter(DBSess.id == Session_id).first()
        if db_session and not db_session.is_active:
            db_session = None

    if not db_session:
        db_session = DBSess(
            id=str(uuid.uuid4()),
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=1),
            is_active=True
        )
        db.add(db_session)
        db.commit()
        db.refresh(db_session)

    # Set session cookie in response
    response = templates.TemplateResponse("login.html", {"request": request})
    response.set_cookie(
        key="session_id", 
        value=db_session.id,
        httponly=True,
        # secure=True,
    )
    return response
