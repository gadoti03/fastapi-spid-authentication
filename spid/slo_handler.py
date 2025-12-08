from settings import settings

from fastapi.responses import HTMLResponse

import uuid, json
from datetime import datetime, timezone
from lxml import etree

from spid.exceptions import SpidConfigError, SpidValidationError 
from spid.utils import base64_to_pem, verify_saml_signature_external

IDPS_FILE = settings.IDPS_FILE

def generate_logout_request(session_id: str, idp_name_qualifier: str, idp_slo_url: str):
    
    sp_entity_id = settings.ENTITY_ID
    sp_name_qualifier = settings.NAME_QUALIFIER
    
    xml, request_id = generate_logout_request_xml(sp_entity_id, sp_name_qualifier, session_id, idp_name_qualifier, idp_slo_url)
    return xml, request_id


def generate_logout_request_xml(sp_entity_id: str, sp_name_qualifier: str, session_id: str, idp_name_qualifier: str, idp_slo_url: str):
    
    # ID e timestamp
    request_id = "_" + str(uuid.uuid4())
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Namespace
    NSMAP = {
        'samlp': "urn:oasis:names:tc:SAML:2.0:protocol",
        'saml': "urn:oasis:names:tc:SAML:2.0:assertion"
    }

    # Root LogoutRequest
    logout_request = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest",
        nsmap=NSMAP,
        ID=request_id,
        Version="2.0",
        IssueInstant=issue_instant,
        Destination=idp_slo_url
    )

    # Issuer
    issuer = etree.SubElement(
        logout_request,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer",
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
        NameQualifier=sp_name_qualifier
    )
    issuer.text = sp_entity_id

    # NameID (identifica l’utente)
    name_id = etree.SubElement(
        logout_request,
        "{urn:oasis:names:tc:SAML:2.0:assertion}NameID",
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        NameQualifier=idp_name_qualifier
    )

    # SessionIndex
    session_index = etree.SubElement(logout_request, "{urn:oasis:names:tc:SAML:2.0:protocol}SessionIndex")
    session_index.text = session_id

    # Serializzazione XML
    xml_bytes = etree.tostring(logout_request, pretty_print=True, xml_declaration=False, encoding="UTF-8")
    return xml_bytes.decode("utf-8"), request_id

def render_logout_form(slo_url: str, saml_request: str, relay_state: str) -> HTMLResponse:

    html_content = f"""
    <html>
        <body onload="document.forms[0].submit()">
            <form action="{slo_url}" method="post">
                <input type="hidden" name="SAMLRequest" value="{saml_request}">
                <input type="hidden" name="RelayState" value="{relay_state}">
                <button type="submit">Logout SPID</button>
            </form>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

def verify_saml_signature(query_string: str, signature: bytes, sig_alg: str, xml_str: str) -> bool:
    """
    Verifica la firma della query string per SLO SPID.
    """
    # Estrai l'issuer dal SAMLResponse XML
    try:
        root = etree.fromstring(xml_str.encode("utf-8"))
        issuer_node = root.xpath(".//saml:Issuer", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})[0]
        issuer_value = issuer_node.text.strip()
    except Exception:
        raise Exception("Impossible to extract Issuer from SAMLResponse")

    # Carica i certificati dell'IdP
    try:
        with open(IDPS_FILE, "r") as f:
            idps = json.load(f)
        idp_info = idps.get(issuer_value)
        certs_b64 = idp_info.get("signing_certificate_x509", [])
        if not certs_b64:
            raise Exception(f"No certificates found for IdP {issuer_value}")
    except Exception as e:
        raise Exception(f"Error loading IdP certificates: {e}")

    # Verifica la firma con tutti i certificati disponibili
    for b64_cert in certs_b64:
        pem_cert = base64_to_pem(b64_cert)
        try:
            if verify_saml_signature_external(query_string, signature, sig_alg, pem_cert):
                return True
        except Exception:
            continue

    return False