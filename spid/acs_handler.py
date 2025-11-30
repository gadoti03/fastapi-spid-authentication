import xmlsec
import lxml.etree as ET
import base64

def verify_saml_signature(xml_str: str, idp_cert_path: str) -> bool:
    # Parse con lxml (xmlsec lavora meglio con lxml)
    root = ET.fromstring(xml_str)

    # Trova il nodo Signature
    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    if signature_node is None:
        raise ValueError("Signature node not found in SAMLResponse")

    # Crea un contesto di verifica
    ctx = xmlsec.SignatureContext()
    
    # Carica il certificato IdP
    key = xmlsec.Key.from_file(idp_cert_path, xmlsec.constants.KeyDataFormatCertPem)
    ctx.key = key

    # Verifica la firma
    try:
        ctx.verify(signature_node)
        return True
    except xmlsec.VerificationError:
        return False

def extract_spid_attributes(saml_response_b64: str) -> dict:
    root = ET.fromstring(saml_response_b64)

    # Namespace SAML
    ns = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
    }

    # Trova tutti gli Attribute e estrai i valori
    attributes = {}
    for attr in root.findall(".//saml:Attribute", ns):
        name = attr.get("Name")
        value_el = attr.find("saml:AttributeValue", ns)
        value = value_el.text if value_el is not None else None

        # CODICE FISCALE E COMUNE DI RESIDENZA
        if name == "fiscalNumber":
            attributes["codice_fiscale"] = value
        elif name == "domicileMunicipality":
            attributes["residenza"] = value

    return attributes