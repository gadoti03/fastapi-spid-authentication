import textwrap
import xmlsec
import json

import lxml.etree as etree

from settings import settings
from spid.utils import get_key_path

IDPS_FILE = settings.IDPS_FILE

def verify_saml_signature(xml_str: str) -> bool:
    root = etree.fromstring(xml_str)
    xmlsec.tree.add_ids(root, ["ID"])

    # Find Signature node
    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    if signature_node is None:
        raise ValueError("Signature node not found in SAMLResponse")

    # Get Reference URI
    ref_node = signature_node.find(".//{http://www.w3.org/2000/09/xmldsig#}Reference")
    if ref_node is None:
        raise ValueError("Reference node not found in Signature")
    
    reference_uri = ref_node.get("URI")
    if not reference_uri or not reference_uri.startswith("#"):
        raise ValueError(f"Reference URI invalid: {reference_uri}")
    reference_id = reference_uri[1:]  # remove the #

    # Find the node signed by the Reference ID
    signed_nodes = root.xpath(f"//*[@ID='{reference_id}']", namespaces=root.nsmap)
    if not signed_nodes:
        raise ValueError(f"Signed node with ID {reference_id} not found")
    signed_node = signed_nodes[0]

    # Find Issuer to identify IdP
    issuer_node = signed_node.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    if issuer_node is None:
        issuer_node = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    if issuer_node is None or issuer_node.text is None:
        raise ValueError("Issuer not found in SAMLResponse")
    issuer_value = issuer_node.text

    # Load IdP certificates
    with open(IDPS_FILE, "r") as f:
        idps = json.load(f)
    idps_info = idps.get(issuer_value)
    if not idps_info:
        raise ValueError(f"No IdP info found for issuer {issuer_value}")
    certs_list = idps_info.get("signing_certificate_x509", [])
    if not certs_list:
        raise ValueError(f"No certificates found for IdP {issuer_value}")

    # Verify signature with all certificates
    verified = False
    for b64_cert in certs_list:
        pem_cert = base64_to_pem(b64_cert)
        try:
            key = xmlsec.Key.from_memory(pem_cert, xmlsec.constants.KeyDataFormatCertPem)
            ctx = xmlsec.SignatureContext()
            ctx.key = key
            ctx.verify(signature_node)
            verified = True
            print(f"Signature verified with certificate:\n{pem_cert}")
            break
        except xmlsec.Error as e:
            print(f"Verification failed with this certificate: {e}")
            continue

    if not verified:
        print("Signature verification failed with all provided certificates")
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
    # Trova l'EncryptedAssertion
    enc_node = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion")
    if enc_node is None:
        # Se non c'è, ritorna l'Assertion in chiaro
        return root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")

    # Carica chiave privata SP
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