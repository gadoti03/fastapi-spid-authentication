from fastapi import HTTPException
from fastapi.responses import HTMLResponse

import base64
import json
import zlib
import uuid
from datetime import datetime, timezone

from lxml import etree
from signxml import XMLSigner, methods

from settings import settings
from spid.utils import get_key_and_cert

KEY_SP_FILE = settings.KEY_SP_FILE
CERT_SP_FILE = settings.CERT_SP_FILE

def get_idp_url(idp: str) -> str:
    IDPS_FILE = settings.IDPS_FILE
    # Load map IDP → URL
    with open(IDPS_FILE, "r") as f:
        idps_data = json.load(f)

    # Check IdP existence
    if idp not in idps_data:
        raise HTTPException(400, "Invalid IdP")
    
    # Get SSO URL
    idp_entry = idps_data.get(idp)
    if not idp_entry:
        raise ValueError(f"IdP {idp} not found")
    
    sso_list = idp_entry.get("single_sign_on_service", [])
    if not sso_list:
        raise ValueError(f"No SingleSignOnService defined for IdP {idp}")
        
    # Find HTTP-Redirect binding
    slo_post = next((slo for slo in sso_list if slo.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), None)
    if slo_post is None:
        raise ValueError(f"No HTTP-POST SingleLogoutService found for IdP {idp}")

    slo_url = slo_post["Location"]
    return slo_url

def generate_authn_request(idp_url: str) -> str:
    sp_entity_id = settings.ENTITY_ID
    name_qualifier = settings.NAME_QUALIFIER           
    acs_url = settings.ACS_URL
    idp_sso_url = idp_url
    xml = generate_authn_request_xml(sp_entity_id, name_qualifier, acs_url, idp_sso_url)
    return xml

def sign_xml(xml_str: str, reference_id: str) -> str:
    # Parsing XML
    parser = etree.XMLParser(remove_blank_text=True)
    xml_doc = etree.fromstring(xml_str.encode("utf-8"), parser=parser)

    # Load key and cert
    cert_data, key_data = get_key_and_cert()
    
    # Creation signer
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-"+settings.MD_ALG,
        digest_algorithm=settings.MD_ALG,
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"
    )
    
    # Find the node to sign by ID
    node_to_sign = xml_doc.xpath(f"//*[@ID='{reference_id}']")[0]
    
    # Sign
    signed_root = signer.sign(node_to_sign, key=key_data, cert=cert_data, reference_uri=f"#{reference_id}")

    # Return signed XML
    return etree.tostring(signed_root, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")

def encode_authn_request(xml: str) -> str:
    print("Original AuthnRequest XML:", xml)
    deflated = zlib.compress(xml.encode())[2:-4]  # DEFLATE without header
    b64_authn = base64.b64encode(deflated).decode()
    return b64_authn

def render_saml_form(idp_url: str, saml_request: str, relay_state: str) -> str:
    html_form = f"""
    <html>
        <body onload="document.forms[0].submit()">
            <form method="POST" action="{idp_url}">
                <input type="hidden" name="SAMLRequest" value="{saml_request}" />
                <input type="hidden" name="RelayState" value="{relay_state}" />
                <noscript>
                    <p>JavaScript is disabled. Click the button below to proceed.</p>
                    <input type="submit" value="Continue" />
                </noscript>
            </form>
        </body>
    </html>
    """
    return HTMLResponse(content=html_form)

def generate_authn_request_xml(sp_entity_id: str, name_qualifier: str, acs_url: str, idp_sso_url: str) -> str:
    # ID univoco e timestamp
    request_id = "_" + str(uuid.uuid4()) # lo devo salvare in qualche db?
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")    
    
    # Namespace
    NSMAP = {
        'samlp': "urn:oasis:names:tc:SAML:2.0:protocol",
        'saml': "urn:oasis:names:tc:SAML:2.0:assertion",
        'ds': "http://www.w3.org/2000/09/xmldsig#"
    }
    
    # Root AuthnRequest - POST Binding
    authn_request = etree.Element("{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
                                  nsmap=NSMAP,
                                  AttributeConsumingServiceIndex="0",
                                  AssertionConsumerServiceURL=acs_url,
                                  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",     # Binding per la risposta
                                  Destination=idp_sso_url,
                                  ForceAuthn="true",
                                  ID=request_id,
                                  IssueInstant=issue_instant,
                                  Version="2.0")
    
    # Issuer
    issuer = etree.SubElement(authn_request, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer",
                              NameQualifier=name_qualifier)
    issuer.text = sp_entity_id
    
    # NameIDPolicy
    nameid_policy = etree.SubElement(authn_request, "{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy",
                                     Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
    
    # RequestedAuthnContext
    requested_authn_context = etree.SubElement(authn_request, "{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext",
                                               Comparison="minimum")
    authn_context_class_ref = etree.SubElement(requested_authn_context,
                                               "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef")
    authn_context_class_ref.text = "https://www.spid.gov.it/SpidL1"     # Livello di autenticazione minimo richiesto
    
    # Serialization XML
    xml_bytes = etree.tostring(authn_request, pretty_print=True, xml_declaration=False, encoding="UTF-8")
    return xml_bytes.decode("utf-8"), request_id
