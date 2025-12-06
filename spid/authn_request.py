from fastapi.responses import HTMLResponse

import json
import uuid
from datetime import datetime, timezone

from lxml import etree

from settings import settings

from spid.exceptions import SpidConfigError

def get_idp_url(idp: str) -> str:

    IDPS_FILE = settings.IDPS_FILE

    try:
        # Load map IDP → URL
        with open(IDPS_FILE, "r") as f:
            idps_data = json.load(f)
    except Exception as e:
        raise SpidConfigError(f"Error loading IdPs file: {e}")

    # Check IdP existence
    if idp not in idps_data:
        raise SpidConfigError(f"Unknown IdP: {idp}")
    
    # Get SSO URL
    idp_entry = idps_data.get(idp)
    if not idp_entry:
        raise SpidConfigError(f"IdP {idp} not found")
    
    sso_list = idp_entry.get("single_sign_on_service", [])
    if not sso_list:
        raise SpidConfigError(f"No SingleSignOnService defined for IdP {idp}")
        
    # Find HTTP-Redirect binding 
    slo_post = next((slo for slo in sso_list if slo.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), None)
    if slo_post is None:
        raise SpidConfigError(f"No HTTP-POST SingleLogoutService found for IdP {idp}")

    slo_url = slo_post["Location"]
    if not slo_url:
        raise SpidConfigError(f"No Location found for HTTP-POST SingleLogoutService for IdP {idp}")
    
    return slo_url

def generate_authn_request(idp_url: str) -> str:

    sp_entity_id = settings.ENTITY_ID
    name_qualifier = settings.NAME_QUALIFIER           
    acs_url = settings.ACS_URL
    idp_sso_url = idp_url
    xml, request_id = generate_authn_request_xml(sp_entity_id, name_qualifier, acs_url, idp_sso_url)
    return xml, request_id

def generate_authn_request_xml(sp_entity_id: str, name_qualifier: str, acs_url: str, idp_sso_url: str) -> str:
 
    # ID and timestamp
    request_id = "_" + str(uuid.uuid4())
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")    
    
    # Namespace
    NSMAP = {
        'samlp': "urn:oasis:names:tc:SAML:2.0:protocol",
        'saml': "urn:oasis:names:tc:SAML:2.0:assertion"#,
        # 'ds': "http://www.w3.org/2000/09/xmldsig#"
    }

    format_value = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    
    # Root AuthnRequest - POST Binding
    authn_request = etree.Element("{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
                                nsmap=NSMAP,
                                ID=request_id,
                                Version="2.0",
                                IssueInstant=issue_instant,
                                Destination=idp_sso_url,
                                # ForceAuthn="true",   # for SPID 2,3
                                AssertionConsumerServiceURL=acs_url,
                                ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                                AttributeConsumingServiceIndex="0"
                                )
    
    # Issuer
    issuer = etree.SubElement(authn_request, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer",
                              NameQualifier=name_qualifier,
                              Format=format_value)
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
    xml_bytes = etree.tostring(authn_request, pretty_print=False, xml_declaration=False, encoding="UTF-8")
    return xml_bytes.decode("utf-8"), request_id

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
