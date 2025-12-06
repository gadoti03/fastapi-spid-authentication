import base64
from settings import settings

import os
from lxml import etree
import xmlsec
from signxml import XMLSigner, methods

from spid.exceptions import SpidSignatureError, SpidConfigError 

def get_key_and_cert():

    NEW_CERT_PATH = os.path.join(settings.CERT_DIR_PATH, "new/crt.pem")
    NEW_KEY_PATH  = os.path.join(settings.CERT_DIR_PATH, "new/key.pem")

    OLD_CERT_PATH = os.path.join(settings.CERT_DIR_PATH, "old/crt.pem")
    OLD_KEY_PATH  = os.path.join(settings.CERT_DIR_PATH, "old/key.pem")
    
    new_exists = os.path.isfile(NEW_CERT_PATH) and os.path.isfile(NEW_KEY_PATH)
    old_exists = os.path.isfile(OLD_CERT_PATH) and os.path.isfile(OLD_KEY_PATH)

    # No certificate → error
    if not new_exists and not old_exists:
        raise SpidConfigError("Rotation error: no certificates found in NEW or OLD directories.")

    # If both exist → OLD is the “stable” certificate
    if new_exists and old_exists:
        try:
            with open(OLD_CERT_PATH, "r") as fcert, open(OLD_KEY_PATH, "r") as fkey:
                return fcert.read(), fkey.read()
        except Exception as e:
            raise SpidConfigError(f"Error loading OLD certificates: {e}")

    # If OLD does not exist → use NEW (initial phase)
    if new_exists:
        try:
            with open(NEW_CERT_PATH, "r") as fcert, open(NEW_KEY_PATH, "r") as fkey:
                return fcert.read(), fkey.read()
        except Exception as e:
            raise SpidConfigError(f"Error loading NEW certificates: {e}")

    # Corrupted state: OLD partially present
    raise SpidConfigError("Invalid rotation state: OLD certificate directory is incomplete.")

def get_key_path():

    OLD_KEY_PATH  = os.path.join(settings.CERT_DIR_PATH, "old/key.pem")
    NEW_KEY_PATH  = os.path.join(settings.CERT_DIR_PATH, "new/key.pem")

    old_exists = os.path.isfile(OLD_KEY_PATH)
    new_exists = os.path.isfile(NEW_KEY_PATH)

    if old_exists:
        return OLD_KEY_PATH
    elif new_exists:
        return NEW_KEY_PATH
    else:
        raise SpidConfigError("No SP private key found in OLD or NEW directories.")

def get_cert_path():

    OLD_CERT_PATH  = os.path.join(settings.CERT_DIR_PATH, "old/crt.pem")
    NEW_CERT_PATH  = os.path.join(settings.CERT_DIR_PATH, "new/crt.pem")

    old_exists = os.path.isfile(OLD_CERT_PATH)
    new_exists = os.path.isfile(NEW_CERT_PATH)

    if old_exists:
        return OLD_CERT_PATH
    elif new_exists:
        return NEW_CERT_PATH
    else:
        raise SpidConfigError("No SP cert key found in OLD or NEW directories.")
    
def sign_xml(xml_str: str, key_path: str, cert_path: str, after_tag: str = None) -> str:

    try:
        # Load key
        with open(key_path, "r") as fkey:
            key_data = fkey.read()
        # Load cert
        with open(cert_path, "r") as fcert:
            cert_data = fcert.read()
    except Exception as e:
        raise SpidConfigError(f"Error loading key or certificate: {e}")
    
    # Parse XML
    parser = etree.XMLParser(remove_blank_text=True)
    root = etree.fromstring(xml_str, parser=parser)

    # Register ID attributes
    xmlsec.tree.add_ids(root, ["ID"])

    # Find the node to sign by ID
    id_nodes = root.xpath("//*[@ID]")
    if not id_nodes:
        raise SpidConfigError("No node with ID attribute found to sign.")    

    # Create signer
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-" + settings.MD_ALG,
        digest_algorithm=settings.MD_ALG,
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"
    )

    id_node = id_nodes[0]
    reference_id = id_node.get("ID")
    node_to_sign = root.xpath(f"//*[@ID='{reference_id}']")[0]

    try:
        # Sign the node
        signed_root = signer.sign(
            node_to_sign,
            key=key_data,
            cert=cert_data,
            reference_uri=f"#{reference_id}"
        )
    except Exception as e:
        raise SpidSignatureError(f"Error signing XML: {e}")

    # --- Move <ds:Signature> after a specific child if requested ---
    if after_tag:
        signature = signed_root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        signed_root.remove(signature)

        target_index = None
        for i, child in enumerate(node_to_sign):
            if child.tag.endswith(after_tag):
                target_index = i
                break
        if target_index is not None:
            signed_root.insert(target_index + 1, signature)
    
    return etree.tostring(signed_root, pretty_print=False, xml_declaration=False, encoding="UTF-8").decode("utf-8")

def verify_xml_signature(xml_str: str, cert_path: str, cert_data: str) -> bool:

    if (not cert_path and not cert_data) or (cert_path and cert_data):
        raise Exception("Provide either cert_path or cert_data, not both or neither.")
    
    try:
        # Load cert
        with open(cert_path, "r") as fcert:
            cert_data = fcert.read()
    except Exception as e:
        raise SpidConfigError(f"Error loading certificate: {e}")

    # Parse XML
    # parser = etree.XMLParser(remove_blank_text=True)
    root = etree.fromstring(xml_str) # , parser=parser)

    # Register ID attributes
    xmlsec.tree.add_ids(root, ["ID"])

    # Find Signature node
    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    if signature_node is None:
        raise SpidConfigError("Signature node not found in XML")

    # Verify signature
    try:
        key = xmlsec.Key.from_memory(cert_data, xmlsec.constants.KeyDataFormatCertPem)
        ctx = xmlsec.SignatureContext()
        ctx.key = key
        ctx.verify(signature_node)
        return True
    except xmlsec.Error as e:
        print(f"Signature verification failed: {e}")
        return False
    
def encode_b64(xml: str) -> str:

    xml_bytes = xml.encode("utf-8")

    b64_authn = base64.b64encode(xml_bytes).decode()
    return b64_authn