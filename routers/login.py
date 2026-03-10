from fastapi import APIRouter
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse


from fastapi import Depends
from sqlalchemy.orm import Session
from database.connection import get_db

from database.models import Session as DBSess

from crud.session import get_or_create_session_by_session_id

from datetime import datetime, timedelta
import uuid

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/login", response_class=Response) # response_class=Response: avoid default JSON response
async def login(request: Request, db: Session = Depends(get_db)):
        
    # Get session ID from cookies
    session_id = request.cookies.get("session_id")
    
    # Get existing session or create new one if not valid
    db_session = get_or_create_session_by_session_id(db, session_id)

    # Set session cookie in response
    response = templates.TemplateResponse("home.html", {"request": request})
    response.set_cookie(
        key="session_id", 
        value=db_session.id,
        httponly=True,
        # secure=True,
    )
    return response
