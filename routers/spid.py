import os, json, base64
import xml.etree.ElementTree as ET
from fastapi import APIRouter, Request, Depends, Response, HTTPException, Form
from fastapi.responses import HTMLResponse, Response, FileResponse, RedirectResponse

from schemas.models import SpidLoginRequest

from spid.authn_request import generate_authn_request, sign_xml, encode_authn_request
from spid.acs_handler import verify_saml_signature, extract_spid_attributes

router = APIRouter()

METADATA_FILE = os.path.join(os.path.dirname(__file__), "../spid/static/metadata.xml")
IDPS_FILE = os.path.join(os.path.dirname(__file__), "../spid/static/idps_map.json")
CERT_IDP_FILE = os.path.join(os.path.dirname(__file__), "../spid/static/certs/crt_idp.pem")
KEY_SP_FILE = os.path.join(os.path.dirname(__file__), "../spid/static/certs/key.pem")
CERT_SP_FILE = os.path.join(os.path.dirname(__file__), "../spid/static/certs/crt_sp.pem")

@router.get("/metadata", response_class=Response) # response_class=Response: avoid default JSON response
async def get_metadata():
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/xml")
    else:
        return Response(content="Metadata not found", status_code=404)
    
@router.post("/login")
async def spid_login(idp: str = Form(...), relay: str = Form("")): # data: SpidLoginRequest
    # idp = data.idp
    # relay = data.relay_state or "" # se è vuoto e stringa vuota da errore -> metti pagina di default

    # Load map IDP → URL
    with open(IDPS_FILE, "r") as f:
        idps_map = json.load(f)

    if idp not in idps_map:
        raise HTTPException(400, "Invalid IdP")
    
    idp_url = idps_map[idp]

    # Generate the AuthnRequest XML
    xml, request_id = generate_authn_request(idp_url)

    # Sign the XML
    xml = sign_xml(xml, request_id, KEY_SP_FILE, CERT_SP_FILE)

    # Base64 encode
    saml_request = encode_authn_request(xml)

    # 5. HTML con form auto-submit
    html = f"""
    <!DOCTYPE html>
    <html>
        <body onload="document.forms[0].submit()">
            <form method="POST" action="{idp_url}">
                <input type="hidden" name="SAMLRequest" value="{saml_request}" />
                <input type="hidden" name="RelayState" value="{relay}" />
                <noscript><button type="submit">Continue</button></noscript>
            </form>
        </body>
    </html>
    """

    return HTMLResponse(content=html)

@router.post("/acs")
async def acs_endpoint(SAMLResponse: str = Form(...), RelayState: str = Form("")):
    decoded_xml = base64.b64decode(SAMLResponse)

    if not verify_saml_signature(decoded_xml, CERT_IDP_FILE):
        raise HTTPException(status_code=401, detail="Invalid SAML signature")
    
    user_attrs = extract_spid_attributes(decoded_xml)
    
    codice_fiscale = user_attrs.get("codice_fiscale")
    residenza = user_attrs.get("residenza")
    print(f"Utente autenticato: CF={codice_fiscale}, Residenza={residenza}")
    
    redirect_url = RelayState or "/"  # se RelayState è vuoto, vai alla home
    return RedirectResponse(url=redirect_url)

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