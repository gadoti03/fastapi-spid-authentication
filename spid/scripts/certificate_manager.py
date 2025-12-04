#!/usr/bin/env python3
import os
import tempfile
from pathlib import Path
from lxml import etree

def add_certificate_to_metadata(metadata_path: str, cert_path: str):
    """Adds a certificate to the SPSSODescriptor in the metadata XML."""

    MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
    DS_NS = "http://www.w3.org/2000/09/xmldsig#"
    NSMAP = {"md": MD_NS, "ds": DS_NS}

    if not os.path.isfile(metadata_path):
        raise FileNotFoundError(f"File not found: {metadata_path}")
    if not os.path.isfile(cert_path):
        raise FileNotFoundError(f"File not found: {cert_path}")

    def read_cert_pem(cert_path):
        with open(cert_path, "r") as f:
            lines = f.readlines()
        cert_body = [line.strip() for line in lines if "CERTIFICATE" not in line]
        return "".join(cert_body)

    def add_key_descriptor(root, cert_str, use):
        key_descriptor = etree.Element(f"{{{MD_NS}}}KeyDescriptor", use=use)
        # Build child structure inside key_descriptor
        key_info = etree.SubElement(key_descriptor, f"{{{DS_NS}}}KeyInfo")
        x509_data = etree.SubElement(key_info, f"{{{DS_NS}}}X509Data")
        x509_cert = etree.SubElement(x509_data, f"{{{DS_NS}}}X509Certificate")
        x509_cert.text = cert_str

        # Insert as first child of root
        root.insert(0, key_descriptor)

    cert_str = read_cert_pem(cert_path)

    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(metadata_path, parser)
    root = tree.getroot()

    spsso_descriptor = root.find(".//md:SPSSODescriptor", namespaces=NSMAP)
    if spsso_descriptor is None:
        raise ValueError("Cannot find <SPSSODescriptor> in metadata.xml")

    # Add new certificate
    add_key_descriptor(spsso_descriptor, cert_str, "signing")
    add_key_descriptor(spsso_descriptor, cert_str, "encryption")

    # Overwrite the metadata file
    with open(metadata_path, "wb") as f:
        tree.write(f, pretty_print=True, xml_declaration=True, encoding="UTF-8")

def remove_certificate_from_metadata(metadata_path: str, cert_path: str):
    """Removes a certificate from the SPSSODescriptor in the metadata XML."""

    MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
    DS_NS = "http://www.w3.org/2000/09/xmldsig#"
    NSMAP = {"md": MD_NS, "ds": DS_NS}

    if not os.path.isfile(metadata_path):
        raise FileNotFoundError(f"File not found: {metadata_path}")
    if not os.path.isfile(cert_path):
        raise FileNotFoundError(f"File not found: {cert_path}")

    def read_cert_pem(cert_path):
        with open(cert_path, "r") as f:
            lines = f.readlines()
        cert_body = [line.strip() for line in lines if "CERTIFICATE" not in line]
        return "".join(cert_body)

    cert_str = read_cert_pem(cert_path)

    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(metadata_path, parser)
    root = tree.getroot()

    spsso_descriptor = root.find(".//md:SPSSODescriptor", namespaces=NSMAP)
    if spsso_descriptor is None:
        raise ValueError("Cannot find <SPSSODescriptor> in metadata.xml")

    # Find and remove KeyDescriptor elements with matching certificate
    key_descriptors = spsso_descriptor.findall("md:KeyDescriptor", namespaces=NSMAP)
    for kd in key_descriptors:
        x509_cert_elem = kd.find(".//ds:X509Certificate", namespaces=NSMAP)
        if x509_cert_elem is not None and x509_cert_elem.text == cert_str:
            spsso_descriptor.remove(kd)

    # Overwrite the metadata file
    with open(metadata_path, "wb") as f:
        tree.write(f, pretty_print=True, xml_declaration=True, encoding="UTF-8")

# Test main
if __name__ == "__main__":
    # Example usage
    metadata_file = "metadata.xml"
    certificate_file = "crt.pem"

    # Add certificate
    add_certificate_to_metadata(metadata_file, certificate_file)

    # Remove certificate
    remove_certificate_from_metadata(metadata_file, certificate_file)