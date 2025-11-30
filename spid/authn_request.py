import base64
import zlib
import urllib.parse
from lxml import etree
from datetime import datetime, timezone
from decouple import config
import uuid
from signxml import XMLSigner, methods

def generate_authn_request(sp_entity_id: str) -> str:
    sp_entity_id = config("ENTITY_ID")
    name_qualifier = config("NAME_QUALIFIER")           
    acs_url = config("ACS_URL")                         # Location in AssertionConsumerService URL del SP
    idp_sso_url = sp_entity_id                          # deve coincidere con uno degli attributi Location presenti nel tag SingleSignOnService riportato nel metadata dell'IdP  -> map JSON IDP → URL                     
    xml = generate_authn_request_xml(sp_entity_id, name_qualifier, acs_url, idp_sso_url)
    return xml

def encode_authn_request(xml: str) -> str:
    deflated = zlib.compress(xml.encode())[2:-4]  # DEFLATE senza header
    b64_authn = base64.b64encode(deflated).decode()
    return b64_authn

def sign_xml(xml_str: str, reference_id: str, key_path: str, cert_path: str) -> str:
    # Parsing XML
    parser = etree.XMLParser(remove_blank_text=True)
    xml_doc = etree.fromstring(xml_str.encode("utf-8"), parser=parser)

    # Leggo chiave privata e certificato
    # ??? dovrei aggiungere la possibilità di firmare con piu chiavi/certificati

    with open(key_path, "rb") as f:
        key_data = f.read()
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    
    # Creazione firmatore
    signer = XMLSigner(
        method=methods.enveloped,           # firma enveloped
        signature_algorithm="rsa-"+config("MD_ALG"),
        digest_algorithm=config("MD_ALG"),
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"
    )
    
    # Trovo il nodo da firmare tramite ID
    node_to_sign = xml_doc.xpath(f"//*[@ID='{reference_id}']")[0]
    
    # Firma
    signed_root = signer.sign(node_to_sign, key=key_data, cert=cert_data, reference_uri=f"#{reference_id}")
    
    # Restituisco XML firmato
    return etree.tostring(signed_root, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode("utf-8")


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
    
    # Root AuthnRequest
    authn_request = etree.Element("{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
                                  nsmap=NSMAP,
                                  AttributeConsumingServiceIndex="0",
                                  AssertionConsumerServiceURL=acs_url,
                                  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
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
