import os, json, base64
import xml.etree.ElementTree as ET
from fastapi import APIRouter, Request, Depends, Response, HTTPException, Form
from fastapi.responses import HTMLResponse, Response, FileResponse, RedirectResponse
from decouple import config

from schemas.models import SpidLoginRequest

from spid.authn_request import generate_authn_request, sign_xml, encode_authn_request, get_idp_url, render_saml_form
from spid.acs_handler import verify_saml_signature, extract_spid_attributes

router = APIRouter()

METADATA_FILE = config("METADATA_FILE")
IDPS_FILE = config("IDPS_FILE")

@router.get("/metadata", response_class=Response) # response_class=Response: avoid default JSON response
async def get_metadata():
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/xml")
    else:
        return Response(content="Metadata not found", status_code=404)
    
@router.post("/login")
async def spid_login(idp: str = Form(...), relay_state: str = Form("")): # data: SpidLoginRequest   
    relay_state = relay_state or "/" # se è vuoto e stringa vuota da errore -> metti pagina di default

    # get idp url
    idp_url = get_idp_url(idp)
    # generate the AuthnRequest XML
    xml, request_id = generate_authn_request(idp_url)
    # sign the AuthnRequest XML 
    xml = sign_xml(xml, request_id)
    # base64 encode the signed AuthnRequest XML
    saml_request = encode_authn_request(xml)
    # render HTML con form auto-submit
    return render_saml_form(idp_url, saml_request, relay_state)

@router.post("/acs")
async def acs_endpoint(SAMLResponse: str = Form(...), relayState: str = Form("/")):
    decoded_xml = base64.b64decode(SAMLResponse)

    # decrypt 

    # verify signature
    if not verify_saml_signature(decoded_xml):
        raise HTTPException(status_code=401, detail="Invalid SAML signature")
    
    # extract SPID attributes
    user_attrs = extract_spid_attributes(decoded_xml)
    
    codice_fiscale = user_attrs.get("codice_fiscale")
    residenza = user_attrs.get("residenza")
    
    print(f"Utente autenticato: CF={codice_fiscale}, Residenza={residenza}")
    
    return RedirectResponse(url=relayState)

@router.post("/logout/acs")  # ACS = Assertion Consumer Service
async def spid_logout_response(request: Request):
    """
    Endpoint che riceve la LogoutResponse dall'IdP SPID.
    """
    form = await request.form()
    saml_response = form.get("SAMLResponse")  # Base64 encoded

    # 1. decodifica e verifica la risposta
    # 2. aggiorna/cancella sessione locale
    # 3. ridireziona utente a pagina di conferma logout
    return Response("Logout completato", status_code=200)