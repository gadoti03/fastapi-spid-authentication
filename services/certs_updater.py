# da runnare IN QUESTA CARTELLA services/ -> risolvi
# risolvi anche il os.getenv (obiettivo: settings da .env)

#!/usr/bin/env python3
import os
import tempfile
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Carica le variabili dal file .env
load_dotenv()

# Prendi le variabili d'ambiente
COMMON_NAME = os.getenv("COMMON_NAME")
DAYS = int(os.getenv("DAYS", "730"))
ENTITY_ID = os.getenv("ENTITY_ID")
LOCALITY_NAME = os.getenv("LOCALITY_NAME")
ORGANIZATION_IDENTIFIER = os.getenv("ORGANIZATION_IDENTIFIER")
ORGANIZATION_NAME = os.getenv("ORGANIZATION_NAME")
MD_ALG = os.getenv("MD_ALG", "sha512")
KEY_LEN = int(os.getenv("KEY_LEN", "3072"))

# output files
crt = "../spid/static/certs/crt.pem"  #/spid/static/certs/crt.pem
csr = "../spid/static/certs/csr.pem"  #/spid/static/certs/csr.pem
key = "../spid/static/certs/key.pem"  #/spid/static/certs/key.pem

# minimum checks
if KEY_LEN not in [2048, 3072, 4096]:
    raise ValueError("KEY_LEN must be one of [2048, 3072, 4096]")
if MD_ALG not in ["sha256", "sha512"]:
    raise ValueError("MD_ALG must be one of ['sha256','sha512']")
if not all([COMMON_NAME, LOCALITY_NAME, ORGANIZATION_IDENTIFIER, ORGANIZATION_NAME, ENTITY_ID]):
    raise ValueError("Tutte le variabili principali devono essere definite")

# custom OID for SPID
orgid_oid = ""
orgid_label = ""
openssl_ver = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
if "OpenSSL 1.0" in openssl_ver:
    orgid_oid = "organizationIdentifier=2.5.4.97"
    orgid_label = "2.5.4.97 organizationIdentifier organizationIdentifier"

# Generate temporary OpenSSL configuration file
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

# Helper function to run commands
def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Generate self-signed certificate
run(f'openssl req -new -x509 -config "{openssl_conf}" -days {DAYS} -keyout "{key}" -out "{crt}" -extensions req_ext')

# Dump text of the self-signed certificate
print("## --------------------------------------------------------------------------")
print("## Text dump of the self-signed certificate")
print("## --------------------------------------------------------------------------")
print(run(f'openssl x509 -noout -text -in "{crt}"').stdout)

# Generate CSR
run(f'openssl req -config "{openssl_conf}" -key "{key}" -new -out "{csr}"')

# Dump text of the certificate signing request
print("## --------------------------------------------------------------------------")
print("## Text dump of the certificate signing request")
print("## --------------------------------------------------------------------------")
print(run(f'openssl req -in "{csr}" -noout -text').stdout)

# Generate temporary OID file
with tempfile.NamedTemporaryFile("w", delete=False) as f:
    oids_conf = f.name
    f.write(f"""
1.3.76.16.6 agIDcert agIDcert
1.3.76.16.4.2.1 spid-publicsector-SP spid-publicsector-SP
2.5.4.83 uri uri
{orgid_label}
""")

# Dump ASN.1 certificate
print("## --------------------------------------------------------------------------")
print("## ASN.1 dump of the self-signed certificate")
print("## --------------------------------------------------------------------------")
print(run(f'openssl asn1parse -inform PEM -oid "{oids_conf}" -i -in "{crt}"').stdout)

# Find offset CertificatePolicies and dump
offset_cmd = f'openssl asn1parse -inform PEM -oid "{oids_conf}" -i -in "{crt}" | grep "X509v3 Certificate Policies" -A1 | tail -1 | cut -d":" -f1 | sed \'s/^[ \\t]*//\''
offset = run(offset_cmd).stdout.strip()
if offset:
    print("## --------------------------------------------------------------------------")
    print("## ASN.1 dump for CertificatePolicies section")
    print("## --------------------------------------------------------------------------")
    print(run(f'openssl asn1parse -inform PEM -oid "{oids_conf}" -i -in "{crt}" -strparse {offset}').stdout)

# Cleanup
Path(openssl_conf).unlink(missing_ok=True)
Path(oids_conf).unlink(missing_ok=True)
