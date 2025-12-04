#!/usr/bin/env python3
import os
import tempfile
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Carica variabili dal file .env nella stessa cartella dello script
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

def get_env(name, default=None, required=False):
    val = os.getenv(name, default)
    if required and not val:
        raise ValueError(f"Environment variable {name} is required")
    return val

def create_key_and_certificate(cert_path: str, key_path: str, csr_path: str):
    """
    Create a self-signed certificate and a private key.
    - cert_path: output path for crt.pem
    - key_path: output path for key.pem
    - csr_path: output path for csr.pem (optional)
    """

    if not os.path.exists(os.path.dirname(cert_path)):
        os.makedirs(os.path.dirname(cert_path))
    if not os.path.exists(os.path.dirname(key_path)):
        os.makedirs(os.path.dirname(key_path))
    if not os.path.exists(os.path.dirname(csr_path)):
        os.makedirs(os.path.dirname(csr_path))

    # Read main variables from .env
    COMMON_NAME = get_env("COMMON_NAME", required=True)
    LOCALITY_NAME = get_env("LOCALITY_NAME", required=True)
    ORGANIZATION_IDENTIFIER = get_env("ORGANIZATION_IDENTIFIER", required=True)
    ORGANIZATION_NAME = get_env("ORGANIZATION_NAME", required=True)
    ENTITY_ID = get_env("ENTITY_ID", required=True)
    DAYS = int(get_env("DAYS", "730"))
    MD_ALG = get_env("MD_ALG", "sha512")
    KEY_LEN = int(get_env("KEY_LEN", "3072"))

    # minimal checks
    if KEY_LEN not in [2048, 3072, 4096]:
        raise ValueError("KEY_LEN must be one of [2048, 3072, 4096]")
    if MD_ALG not in ["sha256", "sha512"]:
        raise ValueError("MD_ALG must be one of ['sha256','sha512']")

    # Custom OID
    orgid_oid = ""
    orgid_label = ""
    openssl_ver = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    if "OpenSSL 1.0" in openssl_ver:
        orgid_oid = "organizationIdentifier=2.5.4.97"
        orgid_label = "2.5.4.97 organizationIdentifier organizationIdentifier"

    # Generate temporary OpenSSL configuration
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        openssl_conf = f.name
        f.write(f"""
oid_section=spid_oids

[ req ]
default_bits={KEY_LEN}
default_md={MD_ALG}
distinguished_name=dn
encrypt_key=no
prompt=no
req_extensions=req_ext

[ spid_oids ]
agidcert=1.3.76.16.6
spid-publicsector-SP=1.3.76.16.4.2.1
uri=2.5.4.83
{orgid_oid}

[ dn ]
commonName={COMMON_NAME}
countryName=IT
localityName={LOCALITY_NAME}
organizationIdentifier={ORGANIZATION_IDENTIFIER}
organizationName={ORGANIZATION_NAME}
uri={ENTITY_ID}

[ req_ext ]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
certificatePolicies=@agid_policies,@spid_policies

[ agid_policies ]
policyIdentifier=agidcert
userNotice=@agidcert_notice

[ agidcert_notice ]
explicitText="agIDcert"

[ spid_policies ]
policyIdentifier=spid-publicsector-SP
userNotice=@spid_notice

[ spid_notice ]
explicitText="cert_SP_Pub"
""")

    def run(cmd):
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)

    # Generate self-signed certificate and key
    run(f'openssl req -new -x509 -config "{openssl_conf}" -days {DAYS} -keyout "{key_path}" -out "{cert_path}" -extensions req_ext')

    # Generate CSR
    run(f'openssl req -config "{openssl_conf}" -key "{key_path}" -new -out "{csr_path}"')

    # Print textual outputs (optional)
    print("### Certificate created:", cert_path)
    print(run(f'openssl x509 -noout -text -in "{cert_path}"').stdout)
    print("### CSR created:", csr_path)
    print(run(f'openssl req -in "{csr_path}" -noout -text').stdout)

    # Cleanup
    Path(openssl_conf).unlink(missing_ok=True)

# Test main
if __name__ == "__main__":
    create_key_and_certificate("./crt.pem", "./key.pem", './csr.pem')
