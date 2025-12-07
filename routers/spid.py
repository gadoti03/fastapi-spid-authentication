from settings import settings

from fastapi import APIRouter, Request, Query, Depends, Response, HTTPException, Form
from fastapi.responses import Response, FileResponse, RedirectResponse

import os, base64
import xml.etree.ElementTree as ET

from schemas.models import SpidLoginRequest
from spid.exceptions import SpidConfigError, SpidSignatureError
from spid.authn_request import generate_authn_request, get_idp_url, render_saml_form
from spid.acs_handler import verify_saml_signature, verify_saml_status, extract_spid_attributes
from spid.slo_handler import generate_logout_request
from spid.utils import get_key_path, get_cert_path, sign_xml, encode_b64, get_field_in_xml
# from spid.slo_handler import 

router = APIRouter()

METADATA_FILE = settings.METADATA_FILE

@router.get("/metadata", response_class=Response) # response_class=Response: avoid default JSON response
async def get_metadata():
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/xml")
    else:
        raise HTTPException(status_code=404, detail="Metadata not found")
    
@router.post("/login")
async def spid_login(idp: str = Form(...), relay_state: str = Form("")): # data: SpidLoginRequest    
    relay_state = relay_state or "/" # se è vuoto e stringa vuota da errore -> metti pagina di default
    
    try:
        # get idp url
        idp_url = get_idp_url(idp)
        
        # generate the AuthnRequest XML
        xml, request_id = generate_authn_request(idp_url)
        #   -> maybe request_is should be saved
        
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
async def acs_endpoint(SAMLResponse: str = Form(...), relayState: str = Form("/")):
    print("LKKKK")
    decoded_xml = base64.b64decode(SAMLResponse)
    
    with open("response.xml", "w") as f:
        f.write(decoded_xml.decode())

    # verify signature
    if not verify_saml_signature(decoded_xml):
        raise HTTPException(status_code=401, detail="Invalid SAML signature")
    
    # verify status
    # if not verify_saml_status(decoded_xml):
    #    raise HTTPException(status_code=403, detail="Authentication Failed")
    
    # get SessionIndex
    sessionIndex = get_field_in_xml(decoded_xml, "SessionIndex")
    if not sessionIndex:
        raise HTTPException(status_code=403, detail="Authentication Failed")
    print("SessionIndex =", sessionIndex)

    with open("session.txt", "w") as f:
        f.write(sessionIndex)

    # TODO:
    # 0) login solo per gli autenticati
    # 2) gestione sessione

    # extract SPID attributes
    user_attrs = extract_spid_attributes(decoded_xml)
    
    codice_fiscale = user_attrs.get("codice_fiscale")
    residenza = user_attrs.get("residenza")
    
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

    # generate LogoutRequest
    xml, request_id = generate_logout_request(session, idp_name_qualifier, url_slo)

    # sign the LogoutRequest XML 
    xml = sign_xml(xml_str = xml, key_path = get_key_path(), cert_path = get_cert_path(), after_tag="SessionIndex")
    
    # base64 encode the signed LogoutRequest XML
    saml_request = encode_b64(xml)
    
    # render HTML con form auto-submit
    return render_saml_form(url_slo, saml_request, relay_state)

@router.post("/slo")
async def spid_slo(SAMLResponse: str, RelayState: str | None = None, SigAlg: str | None = None, Signature: str | None = None):
    print("hbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    
@router.get("/slo")
async def spid_slo(SAMLResponse: str, RelayState: str | None = None, SigAlg: str | None = None, Signature: str | None = None):
    
    #  ricevo 4 campi
    # devo capire se tutti inviano 4 campi

    decoded_xml = base64.b64decode(SAMLResponse)

    with open("proof.xml", "w") as f:
        f.write()

    return
    form = await request.form()
    saml_response = form.get("SAMLResponse")  # Base64 encoded

    # 1. decodifica e verifica la risposta
    # 2. aggiorna/cancella sessione locale
    # 3. ridireziona utente a pagina di conferma logout
    return Response("Logout completato", status_code=200)