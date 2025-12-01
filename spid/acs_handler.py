import textwrap
from decouple import config
import xmlsec
import lxml.etree as ET
import json

IDPS_FILE = config("IDPS_FILE")
KEY_SP_FILE = config("KEY_SP_FILE")


def verify_saml_signature(xml_str: str) -> bool:
    root = ET.fromstring(xml_str)

    # Find Signature node
    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    if signature_node is None:
        raise ValueError("Signature node not found in SAMLResponse")
    
    # Decrypt assertion if encrypted
    assertion_node = decrypt_assertion(root, KEY_SP_FILE)

    # Find Issuer to identify IdP
    issuer_node = assertion_node.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    if issuer_node is None:
        raise ValueError("Tag Issuer not found in SAMLResponse")
    issuer_value = issuer_node.text

    # Load IdP certificates from IDPS_FILE
    with open(IDPS_FILE, "r") as f:
        idps = json.load(f)

    idps_info = idps.get(issuer_value)
    if idps_info is None:
        raise ValueError(f"IdP entity not found for issuer: {issuer_value}")
    
    certs_list = idps_info.get("certs", [])
    if not certs_list:
        raise ValueError(f"No certificates found for IdP entity: {issuer_value}")

    # Convert base64 cert to PEM format
    def base64_to_pem(b64_cert: str) -> str:
        pem = "-----BEGIN CERTIFICATE-----\n"
        pem += "\n".join(textwrap.wrap(b64_cert, 64))
        pem += "\n-----END CERTIFICATE-----\n"
        return pem

    # verify signature with each cert until one works
    verified = False
    for b64_cert in certs_list:
        pem_cert = base64_to_pem(b64_cert)
        try:
            key = xmlsec.Key.from_memory(pem_cert, xmlsec.constants.KeyDataFormatCertPem)
            ctx = xmlsec.SignatureContext()
            ctx.key = key
            ctx.verify(signature_node)
            verified = True
            print("Signature verified with this certificate")
            break
        except xmlsec.VerificationError:
            continue

    if not verified:
        print("Signature verification failed with all provided certificates ❌")
        return False
    
    return True

def extract_spid_attributes(saml_response_b64: str) -> dict:
    root = ET.fromstring(saml_response_b64)

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