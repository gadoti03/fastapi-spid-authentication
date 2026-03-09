from settings import settings

from fastapi import APIRouter, Request, Query, Depends, Response, HTTPException, Form
from fastapi.responses import Response, FileResponse, RedirectResponse

import os, base64, zlib
import xml.etree.ElementTree as ET
from urllib.parse import quote, unquote

from schemas.models import SpidLoginRequest
from spid.exceptions import SpidConfigError, SpidSignatureError, SpidInternalError
from spid.authn_request import generate_authn_request, get_idp_url, render_saml_form
from spid.acs_handler import verify_saml_signature as verify_saml_signature_acs, verify_saml_status, extract_spid_attributes
from spid.slo_handler import generate_logout_request, verify_saml_signature as verify_saml_signature_slo
from spid.utils import get_key_path, get_cert_path, sign_xml, encode_b64, get_field_in_xml, parse_query, verify_saml_status

from sqlalchemy.orm import Session
from database.connection import get_db

from crud.session import get_session, update_session_with_spid_info
from crud.saml_request import create_saml_request, use_saml_request
from crud.user import create_user, get_user_by_cf

router = APIRouter()

METADATA_FILE = settings.METADATA_FILE

@router.get("/metadata", response_class=Response) # response_class=Response: avoid default JSON response
async def get_metadata():
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/xml")
    else:
        raise HTTPException(status_code=404, detail="Metadata not found")
    
@router.post("/login")
async def spid_login(request: Request, db: Session = Depends(get_db), idp: str = Form(...), relay_state: str = Form("")): # data: SpidLoginRequest    
    relay_state = relay_state or "/" # se è vuoto e stringa vuota da errore -> metti pagina di default

    # Get session ID from cookies
    session_id = request.cookies.get("session_id")

    # Get existing session or create new one if not valid
    db_session = get_session(db, session_id)
    
    try:
        # get idp url
        idp_url = get_idp_url(idp)
        
        # generate the AuthnRequest XML
        xml, request_id = generate_authn_request(idp_url)
        
        # save the SAML request in the database
        create_saml_request(db, request_id, db_session.id, "AuthnRequest")

        print("Request ID /login:", request_id)
        
        # sign the AuthnRequest XML 
        xml = sign_xml(xml_str = xml, key_path = get_key_path(), cert_path = get_cert_path(), after_tag="Issuer")
        
        # base64 encode the signed AuthnRequest XML
        saml_request = encode_b64(xml)

        # render HTML con form auto-submit
        return render_saml_form(idp_url, saml_request, relay_state)
    
    except SpidConfigError as e:
        raise HTTPException(status_code=500, detail=f"SPID Configuration Error: {e}")
    except SpidSignatureError as e:
        raise HTTPException(status_code=500, detail=f"SPID Signature Error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")

@router.post("/acs")
async def acs_endpoint(db: Session = Depends(get_db), SAMLResponse: str = Form(...), relayState: str = Form("/")):
    decoded_xml = base64.b64decode(SAMLResponse).decode("utf-8")

    # verify signature
    if not verify_saml_signature_acs(decoded_xml):
        raise HTTPException(status_code=401, detail="Invalid SAML signature")
    
    if not verify_saml_status(decoded_xml):
        raise HTTPException(status_code=403, detail="Authentication Failed")
    
    # get SessionIndex
    sessionIndex = get_field_in_xml(decoded_xml, "SessionIndex")
    if not sessionIndex:
        raise HTTPException(status_code=403, detail="Authentication Failed")
    
    print("SessionIndex =", sessionIndex)

    # get RequestID
    request_id = get_field_in_xml(decoded_xml, "InResponseTo")

    # verify that the SAML response corresponds to a valid SAML request in the database
    saml_request = use_saml_request(db, request_id)
    if not saml_request:
        raise HTTPException(status_code=403, detail="Invalid SAML request")

    print("Request ID /acs:", request_id)

    # extract SPID attributes
    user_attrs = extract_spid_attributes(decoded_xml)
    
    codice_fiscale = user_attrs.get("codice_fiscale")
    residenza = user_attrs.get("residenza")

    # verifica vincoli di residenza
    if residenza != settings.REQUIRED_RESIDENCE:
        raise HTTPException(status_code=403, detail="User does not meet residence requirements")
    
    # create user
    user = get_user_by_cf(db, codice_fiscale)
    if not user:
        user = create_user(db, codice_fiscale)

    # update session
    update_session_with_spid_info(db, saml_request.session_id, sessionIndex, codice_fiscale)
    
    print(f"Utente autenticato: CF={codice_fiscale}, Residenza={residenza}")
    
    return RedirectResponse(url=relayState, status_code=302)

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