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
from spid.utils import get_key_path, get_cert_path, sign_xml, encode_b64, get_field_in_xml, parse_query
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
    if not verify_saml_signature_acs(decoded_xml):
        raise HTTPException(status_code=401, detail="Invalid SAML signature")
    
    if not verify_saml_status(decoded_xml):
        raise HTTPException(status_code=403, detail="Authentication Failed")
    
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

    return RedirectResponse(url=relay_state, status_code=302)

































'''
@router.get("/slo")
async def spid_slo(SAMLResponse: str, SigAlg: str, Signature: str, RelayState: str | None = None):
    print(RelayState)
    # Ricostruisci la query string esattamente come firmata dall'IdP
    query_to_verify = f"SAMLResponse={quote(SAMLResponse)}"
    if RelayState is not None:
        query_to_verify += f"&RelayState={quote(RelayState)}"
    query_to_verify += f"&SigAlg={quote(SigAlg)}"

    print(query_to_verify)

    # Decodifica la signature da base64
    try:
        signature_bytes = base64.b64decode(Signature)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Errore decodifica Signature: {e}")

    # Decomprimi e decodifica SAMLResponse per log o eventuale verifica dello Status
    try:
        decoded_xml = zlib.decompress(base64.b64decode(SAMLResponse), -15).decode("utf-8")
        print("SAMLResponse XML:", decoded_xml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Errore decodifica SAMLResponse: {e}")

    # Verifica firma
    if not verify_saml_signature_slo(query_to_verify, signature_bytes, SigAlg, decoded_xml):
        raise HTTPException(status_code=401, detail="Invalid SAML signature")

    # Qui puoi gestire la terminazione della sessione utente
    return {"status": "ok", "message": "SLO completed"}

'''