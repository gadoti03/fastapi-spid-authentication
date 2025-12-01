#!/usr/bin/env python3
"""
Generate SPID-compliant self-signed certificates (key.pem, csr.pem, crt.pem)
based on Avviso SPID n.29 v3.
"""

import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import random_serial_number, PolicyInformation, UserNotice
from dotenv import load_dotenv

# ---------- 0️⃣ Carica variabili dal file .env ----------
load_dotenv(".env")

COMMON_NAME = os.getenv("COMMON_NAME")
LOCALITY_NAME = os.getenv("LOCALITY_NAME")
ORGANIZATION_IDENTIFIER = os.getenv("ORGANIZATION_IDENTIFIER")
ORGANIZATION_NAME = os.getenv("ORGANIZATION_NAME")
ENTITY_ID = os.getenv("ENTITY_ID")
MD_ALG = os.getenv("MD_ALG", "sha512")
KEY_LEN = int(os.getenv("KEY_LEN", 3072))
DAYS_VALID = int(os.getenv("DAYS", 730))

# ---------- 1️⃣ Controlli variabili obbligatorie ----------
for var_name, var_value in [
    ("COMMON_NAME", COMMON_NAME),
    ("LOCALITY_NAME", LOCALITY_NAME),
    ("ORGANIZATION_IDENTIFIER", ORGANIZATION_IDENTIFIER),
    ("ORGANIZATION_NAME", ORGANIZATION_NAME),
    ("ENTITY_ID", ENTITY_ID),
]:
    if not var_value:
        raise ValueError(f"{var_name} must be set in .env")

if KEY_LEN not in [2048, 3072, 4096]:
    raise ValueError("KEY_LEN must be one of [2048, 3072, 4096]")

if MD_ALG not in ["sha256", "sha512"]:
    raise ValueError("MD_ALG must be one of [sha256, sha512]")

# ---------- 2️⃣ Crea cartella output ----------
OUTPUT_DIR = "../spid-compliant-certificates/generated-certs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

key_path = os.path.join(OUTPUT_DIR, "key.pem")
csr_path = os.path.join(OUTPUT_DIR, "csr.pem")
crt_path = os.path.join(OUTPUT_DIR, "crt.pem")

# ---------- 3️⃣ Genera chiave privata ----------
private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_LEN)
with open(key_path, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# ---------- 4️⃣ Genera CSR SPID-compliant ----------
csr_builder = x509.CertificateSigningRequestBuilder()
csr_builder = csr_builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
    x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
    x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
    x509.NameAttribute(ObjectIdentifier("2.5.4.97"), ORGANIZATION_IDENTIFIER),  # organizationIdentifier
    x509.NameAttribute(ObjectIdentifier("2.5.4.83"), ENTITY_ID)  # uri
]))

csr_builder = csr_builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True
)
csr_builder = csr_builder.add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
)
csr_builder = csr_builder.add_extension(
    x509.CertificatePolicies([
        PolicyInformation(
            policy_identifier=ObjectIdentifier("1.3.76.16.6"),  # agIDcert
            user_notices=[UserNotice(explicit_text="agIDcert")]
        ),
        PolicyInformation(
            policy_identifier=ObjectIdentifier("1.3.76.16.4.2.1"),  # spid-publicsector-SP
            user_notices=[UserNotice(explicit_text="cert_SP_Pub")]
        )
    ]),
    critical=True
)

csr = csr_builder.sign(private_key, getattr(hashes, MD_ALG.upper())())
with open(csr_path, "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# ---------- 5️⃣ Genera certificato self-signed SPID-compliant ----------
now = datetime.now(timezone.utc)

cert_builder = x509.CertificateBuilder()
cert_builder = cert_builder.subject_name(csr.subject)
cert_builder = cert_builder.issuer_name(csr.subject)  # self-signed
cert_builder = cert_builder.public_key(private_key.public_key())
cert_builder = cert_builder.not_valid_before(now)
cert_builder = cert_builder.not_valid_after(now + timedelta(days=DAYS_VALID))
cert_builder = cert_builder.serial_number(random_serial_number())

cert_builder = cert_builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True
)
cert_builder = cert_builder.add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
)
cert_builder = cert_builder.add_extension(
    x509.CertificatePolicies([
        PolicyInformation(
            policy_identifier=ObjectIdentifier("1.3.76.16.6"),  # agIDcert
            user_notices=[UserNotice(explicit_text="agIDcert")]
        ),
        PolicyInformation(
            policy_identifier=ObjectIdentifier("1.3.76.16.4.2.1"),  # spid-publicsector-SP
            user_notices=[UserNotice(explicit_text="cert_SP_Pub")]
        )
    ]),
    critical=True
)

certificate = cert_builder.sign(private_key, getattr(hashes, MD_ALG.upper())())
with open(crt_path, "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

# ---------- 6️⃣ Output ----------
print(f"✅ Certificates generated in {OUTPUT_DIR}")
print(f" - Private Key: {key_path}")
print(f" - CSR: {csr_path}")
print(f" - Self-signed certificate: {crt_path}")
