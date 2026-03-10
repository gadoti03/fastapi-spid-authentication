from urllib import response

from settings import settings

from fastapi import APIRouter, Request, Query, Depends, Response, HTTPException, Form
from fastapi.responses import Response, FileResponse, RedirectResponse, HTMLResponse
import os, base64, zlib
import xml.etree.ElementTree as ET
from urllib.parse import quote, unquote

from schemas.models import SpidLoginRequest
from spid.exceptions import SpidConfigError, SpidSignatureError, SpidInternalError
from spid.authn_request import generate_authn_request, get_idp_url, render_saml_form
from spid.acs_handler import verify_saml_signature as verify_saml_signature_acs, verify_saml_status, extract_spid_attributes
from spid.slo_handler import generate_logout_request, verify_saml_signature as verify_saml_signature_slo
from spid.utils import get_key_path, get_cert_path, sign_xml, encode_b64, get_field_in_xml, parse_query, verify_saml_status

from services.spid_service import get_spid_metadata, initiate_authn_request, handle_authn_response

from sqlalchemy.orm import Session
from database.connection import get_db

from crud.session import get_or_create_session_by_session_id, update_session_with_spid_info
from crud.saml_request import create_saml_request, use_saml_request
from crud.user import create_user, get_user_by_cf

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
    html_form = initiate_authn_request(idp, db, db_session, relay_state)

    return HTMLResponse(content=html_form)

@router.post("/acs")
async def acs_endpoint(db: Session = Depends(get_db), SAMLResponse: str = Form(...), relayState: str = Form("/")):
    
    # decode SAMLResponse
    decoded_xml = base64.b64decode(SAMLResponse).decode("utf-8")

    # get eventually updated session_id after handling the SAML response
    session_id = handle_authn_response(decoded_xml, db, relayState)

    # create redirect response
    response = RedirectResponse(url=relayState, status_code=302)

    # update session cookie in response    response = RedirectResponse(url=relayState, status_code=302)
    response.set_cookie(
        key="session_id", 
        value=session_id,
        httponly=True,
        # secure=True,
    )

    return response

@router.get("/logout")
async def spid_logout_request(session: str = Query(...)):
    
    relay_state = "/"
    ################################
    # LETTURA NELLA PROPRIA SESSIONE
    ################################

    '''
    with open("session.txt", "r") as f:
        session = f.read()
    '''

    url_slo = "https://demo.spid.gov.it/samlsso"
    idp_name_qualifier = "https://demo.spid.gov.it"
    ################################
    ################################
    ################################

    # generate LogoutRequest
    xml, request_id = generate_logout_request(session, idp_name_qualifier, url_slo)

    print("Request ID /logout:", request_id)

    # sign the LogoutRequest XML 
    xml = sign_xml(xml_str = xml, key_path = get_key_path(), cert_path = get_cert_path(), after_tag="SessionIndex")
    
    # base64 encode the signed LogoutRequest XML
    saml_request = encode_b64(xml)
    
    # render HTML con form auto-submit
    return render_saml_form(url_slo, saml_request, relay_state)

@router.get("/slo")
async def spid_slo(request: Request):
    
    # get raw query
    raw_query = request.scope["query_string"].decode("utf-8")

    try:
        slo_data = parse_query(raw_query)
    except SpidInternalError as e:
        raise HTTPException(status_code=500, detail=f"Params Invalid Error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")

    decoded_xml = slo_data["decoded_xml"]
    relay_state = slo_data["RelayState"]
    sig_alg = slo_data["SigAlg"]
    signature = slo_data["Signature"]
    query_to_verify = slo_data["query_to_verify"]

    # validate signature
    try:
        if not verify_saml_signature_slo(query_to_verify, signature, sig_alg, decoded_xml):
            raise HTTPException(status_code=401, detail="Invalid SAML signature")
    except SpidSignatureError as e:
        raise HTTPException(status_code=500, detail=f"SPID Signature Error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")

    # verify status
    if not verify_saml_status(decoded_xml):
        raise HTTPException(status_code=500, detail=f"Unsuccessuful Logout")
    
    # get RequestID
    request_id = get_field_in_xml(decoded_xml, "InResponseTo")

    print("Request ID /slo:", request_id)
    
    return RedirectResponse(url=relay_state, status_code=302)