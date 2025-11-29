import os, json
from fastapi import APIRouter, Request, Depends, Response, HTTPException
from fastapi.responses import Response, RedirectResponse

from schemas.models import SpidLoginRequest

from spid.authn_request import generate_authn_request, build_redirect_url

router = APIRouter()

METADATA_FILE = os.path.join(os.path.dirname(__file__), "../spid/static/metadata.xml")
IDPS_FILE = os.path.join(os.path.dirname(__file__), "../spid/static/idps_map.js")

@router.get("/metadata", response_class=Response) # response_class=Response: avoid default JSON response
async def get_metadata():
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r") as f:
            xml_content = f.read()
        return Response(content=xml_content, media_type="application/xml")
    else:
        return Response(content="Metadata not found", status_code=404)
    
@router.post("/login")
async def spid_login(data: SpidLoginRequest):
    idp = data.idp
    # relay = data.relay_state

    with open(IDPS_FILE, "r") as f:
        idps_map = json.load(f)

    if not idp or idp not in idps_map:
        raise HTTPException(status_code=400, detail="Invalid IdP")
    
    idp_url = idps_map[idp]
    
    xml = generate_authn_request(idp_url)
    redirect_url = build_redirect_url(idp_url, xml, data.relay_state)
    return RedirectResponse(redirect_url)

@router.post("/acs")
async def spid_acs(request: Request):
    # ricevi risposta SPID, decodifica SAML, crea sessione
    saml_response = await request.form()
    # verifica firma, estrai attributi, salva sessione
    return {"msg": "SPID login successful"}

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