from settings import settings

import textwrap
import xmlsec
import json
import lxml.etree as etree

from spid.exceptions import SpidConfigError, SpidValidationError 
from spid.utils import verify_xml_signature

IDPS_FILE = settings.IDPS_FILE

def verify_saml_signature(xml_str: str) -> bool:

    root = etree.fromstring(xml_str)

    # Find Issuer to identify IdP
    issuer_node = root.xpath(".//saml:Issuer", namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})
    issuer_node = issuer_node[0]
    
    if issuer_node is None or issuer_node.text is None:
        raise SpidConfigError("Issuer not found in SAMLResponse")
    issuer_value = issuer_node.text

    try:
        # Load IdP certificates
        with open(IDPS_FILE, "r") as f:
            idps = json.load(f)
    except Exception as e:
        raise SpidConfigError(f"Error loading IdPs file: {e}")

    idps_info = idps.get(issuer_value)
    if not idps_info:
        raise SpidConfigError(f"No IdP info found for issuer {issuer_value}")
    certs_list = idps_info.get("signing_certificate_x509", [])
    if not certs_list:
        raise SpidConfigError(f"No certificates found for IdP {issuer_value}")

    # Verify signature with all certificates
    verified = False
    for b64_cert in certs_list:
        pem_cert = base64_to_pem(b64_cert)
        try:
            verified = verify_xml_signature(xml_str = xml_str, cert_data = pem_cert)
            break
        except SpidValidationError as e:
            continue

    if not verified:
        return False

    return True

def extract_spid_attributes(saml_response_b64: str) -> dict:

    root = etree.fromstring(saml_response_b64)

    # Namespace SAML
    ns = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
    }

    # Find all Attribute elements and extract their values
    attributes = {}
    for attr in root.findall(".//saml:Attribute", ns):
        name = attr.get("Name")
        value_el = attr.find("saml:AttributeValue", ns)
        value = value_el.text if value_el is not None else None

        # FISCAL NUMBER and MUNICIPALITY OF RESIDENCE
        if name == "fiscalNumber":
            attributes["codice_fiscale"] = value
        elif name == "domicileMunicipality":
            attributes["residenza"] = value

    return attributes

def decrypt_assertion(root, sp_private_key_path: str):

    # Find the EncryptedAssertion
    enc_node = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion")
    if enc_node is None:
        # If there is not, return the plain root
        return root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")

    # Load private key
    key = xmlsec.Key.from_file(sp_private_key_path, xmlsec.constants.KeyDataFormatPem)
    ctx = xmlsec.DecryptContext(key)
    decrypted_node = ctx.decrypt(enc_node)
    return decrypted_node

def base64_to_pem(b64_cert: str) -> str:

    """Converte un certificato Base64 in formato PEM."""
    pem = "-----BEGIN CERTIFICATE-----\n"
    pem += "\n".join([b64_cert[i:i+64] for i in range(0, len(b64_cert), 64)])
    pem += "\n-----END CERTIFICATE-----\n"
    return pem