#!/usr/bin/env python3
import os
from lxml import etree
import xmlsec

MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
NSMAP = {"md": MD_NS, "ds": DS_NS}

def remove_signature_from_metadata(metadata_path: str):
    """
    Remove eventual digital signature from a SAML metadata.
    Overwrites the original file without the signature.
    """
    def remove_signature(root):
        signature = root.find(".//ds:Signature", namespaces=NSMAP)
        if signature is not None:
            parent = signature.getparent()
            parent.remove(signature)
            
    if not os.path.isfile(metadata_path):
        raise FileNotFoundError(f"File not found: {metadata_path}")

    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(metadata_path, parser)
    root = tree.getroot()

    remove_signature(root)

    tree.write(metadata_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    print(f"[INFO] Signature removed from: {metadata_path}")

def sign_metadata(metadata_path: str, key_path: str, cert_path: str):
    """
    Digital signature of the SAML metadata.
    Overwrites the original file with the signed version.
    """
    def read_cert_pem(cert_path):
        with open(cert_path, "r") as f:
            lines = f.readlines()
        cert_body = [line.strip() for line in lines if "CERTIFICATE" not in line]
        return "".join(cert_body)

    def cert_present_in_metadata(root, cert_str):
        signing_key_descriptors = root.findall(".//md:KeyDescriptor[@use='signing']", namespaces=NSMAP)
        for kd in signing_key_descriptors:
            certs = kd.findall(".//ds:X509Certificate", namespaces=NSMAP)
            for c in certs:
                if c.text is not None and c.text.strip() == cert_str.strip():
                    return True
        return False
    
    for path in (metadata_path, key_path, cert_path):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")

    cert_str = read_cert_pem(cert_path)

    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(metadata_path, parser)
    root = tree.getroot()

    if not cert_present_in_metadata(root, cert_str):
        raise ValueError("Certificate not found in <KeyDescriptor use='signing'>")

    # Not needed to call remove_signature here since we always overwrite the file
    # remove_signature(root)

    tmp_file = metadata_path + ".tmp"
    tree.write(tmp_file, pretty_print=True, xml_declaration=True, encoding="UTF-8")

    try:
        parser = etree.XMLParser(remove_blank_text=True)
        tree = etree.parse(tmp_file, parser)
        root = tree.getroot()

        xmlsec.tree.add_ids(root, ["ID"])
        entity_id = root.get("ID")
        if not entity_id:
            raise ValueError("The root node does not have an ID attribute for signing.")

        sign_node = xmlsec.template.create(
            root, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256, ns="ds"
        )
        root.insert(0, sign_node)

        ref = xmlsec.template.add_reference(
            sign_node, xmlsec.Transform.SHA256, uri="#" + entity_id
        )
        xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
        xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

        key_info = xmlsec.template.ensure_key_info(sign_node)
        xmlsec.template.add_x509_data(key_info)

        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(key_path, xmlsec.KeyFormat.PEM)
        key.load_cert_from_file(cert_path, xmlsec.KeyFormat.PEM)
        ctx.key = key

        ctx.sign(sign_node)

        tree.write(metadata_path, pretty_print=False, xml_declaration=False, encoding="UTF-8")
    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

# Test main
if __name__ == "__main__":
    # Example usage
    metadata_file = "metadata.xml"
    key_file = "key.pem"
    cert_file = "crt.pem"

    try:
        remove_signature_from_metadata(metadata_file)
        sign_metadata(metadata_file, key_file, cert_file)
        print(f"[INFO] Metadata signed successfully: {metadata_file}")
    except Exception as e:
        print(f"[ERROR] {e}") 