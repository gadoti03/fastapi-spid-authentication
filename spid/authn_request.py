import base64
import zlib
import urllib.parse
from datetime import datetime

def generate_authn_request(sp_entity_id: str, destination: str, request_id: str | None = None) -> str:
    """Crea l'XML AuthnRequest SAML"""
    if not request_id:
        request_id = "_123456789"  # puoi generare un UUID vero

    issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    xml = f"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}"
        Destination="{destination}">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{sp_entity_id}</saml:Issuer>
    </samlp:AuthnRequest>"""

    return xml

def encode_authn_request(xml: str) -> str:
    """Comprimi e codifica in base64"""
    deflated = zlib.compress(xml.encode())[2:-4]  # DEFLATE senza header
    b64_authn = base64.b64encode(deflated).decode()
    return b64_authn

def build_redirect_url(idp_url: str, xml: str, relay_state: str | None = None) -> str:
    """Costruisci l'URL completo per il redirect all'IdP"""
    params = {"SAMLRequest": encode_authn_request(xml)}
    if relay_state:
        params["RelayState"] = relay_state
    return f"{idp_url}?{urllib.parse.urlencode(params)}"
