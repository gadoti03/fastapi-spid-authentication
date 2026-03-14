# routers/spid.py
from settings import settings

from fastapi import APIRouter, Request, Depends, Response, Form
from fastapi.responses import Response, RedirectResponse, HTMLResponse

import base64

from sqlalchemy.orm import Session
from database.connection import get_db

from services.spid_service import get_spid_metadata, handle_logout_response, initiate_authn_request, handle_authn_response, initiate_logout_request
from services.session_service import get_or_create_session_by_session_id

from repositories.session_repository import SessionRepository

router = APIRouter()

METADATA_FILE = settings.METADATA_FILE

@router.get("/metadata", response_class=Response) # response_class=Response: avoid default JSON response
async def get_metadata():
    return get_spid_metadata()
    
@router.post("/login")
async def spid_login(request: Request, db: Session = Depends(get_db), idp: str = Form(...), relay_state: str = Form("")): # data: SpidLoginRequest    
    
    relay_state = relay_state or "/" # se è vuoto e stringa vuota da errore -> metti pagina di default

    # get session ID from cookies
    session_id = request.cookies.get("session_id")

    # get existing session or create new one if not valid
    db_session = get_or_create_session_by_session_id(db, session_id)

    # get HTML form with auto-submit to IdP
    html_form = initiate_authn_request(db, idp, db_session, relay_state)

    return HTMLResponse(content=html_form)

@router.post("/acs")
async def acs_endpoint(db: Session = Depends(get_db), SAMLResponse: str = Form(...), RelayState: str = Form("/")):
    
    # decode SAMLResponse
    decoded_xml = base64.b64decode(SAMLResponse).decode("utf-8")

    # get eventually updated session_id after handling the SAML response
    session_id = handle_authn_response(decoded_xml, db)

    # create redirect response
    response = RedirectResponse(url=settings.FRONTEND_PATH + RelayState, status_code=302)

    # costruisco il cookie manualmente, con Partitioned se necessario
    cookie_header = f"session_id={session_id}; Path=/; Secure; HttpOnly; SameSite=None; Partitioned;"
    response.headers["Set-Cookie"] = cookie_header

    return response

@router.get("/logout")
async def spid_logout_request(request: Request, db: Session = Depends(get_db),  relay_state: str = Form("")):
    
    relay_state = relay_state or "/" # se è vuoto e stringa vuota da errore -> metti pagina di default

    # get session ID from cookies
    session_id = request.cookies.get("session_id")

    # get existing session
    db_session = SessionRepository.get_by_session_id(db, session_id)
    
    # get HTML form with auto-submit to IdP
    html_form = initiate_logout_request(db, db_session, relay_state)
    
    # render HTML con form auto-submit
    return HTMLResponse(content=html_form)

@router.get("/slo")
async def spid_slo(request: Request, db: Session = Depends(get_db)):
    
    # get raw query
    raw_query = request.scope["query_string"].decode("utf-8")

    # handle logout response and get relay_state for redirect
    relay_state = handle_logout_response(db, raw_query)
    
    response = RedirectResponse(url=relay_state, status_code=302)

    # update session cookie in response
    response.delete_cookie(key="session_id")

    return response
