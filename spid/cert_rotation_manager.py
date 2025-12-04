#!/usr/bin/env python3
"""
Certificate Rotation Manager

This module manages NEW/OLD certificate rotation for SPID metadata.

It does NOT sign metadata or modify XML directly.
It ONLY decides what to do and calls external functions
(add_certificate, remove_certificate, sign_metadata),
which must be implemented elsewhere.
"""

import os
from dotenv import load_dotenv
from subprocess import run

from scripts.create_cert import create_key_and_certificate
from scripts.certificate_manager import add_certificate_to_metadata, remove_certificate_from_metadata
from scripts.signature_manager import sign_metadata, remove_signature_from_metadata

load_dotenv()

# === CONSTANTS ===============================================================

CERT_DIR_PATH = os.getenv("CERT_DIR_PATH")
METADATA_PATH = os.getenv("METADATA_PATH")
METADATA_CLEAN_PATH = os.getenv("METADATA_CLEAN_PATH")

CERT_DIR_OLD = CERT_DIR_PATH + "/old"
CERT_DIR_NEW = CERT_DIR_PATH + "/new"

NEW_CERT_PATH = CERT_DIR_NEW + "/crt.pem"
NEW_KEY_PATH = CERT_DIR_NEW + "/key.pem"
NEW_CSR_PATH = CERT_DIR_NEW + "/csr.pem"

OLD_CERT_PATH = CERT_DIR_OLD + "/crt.pem"
OLD_KEY_PATH = CERT_DIR_OLD + "/key.pem"
OLD_CSR_PATH = CERT_DIR_OLD + "/csr.pem"

# === UTILITY =================================================================

def file_exists(path: str) -> bool:
    return os.path.isfile(path)

# === MAIN ROTATION LOGIC ======================================================

def add_new_certificate():
    """
    Add a new certificate into the rotation system.

    Logic:
    - If NEW directory is empty:
        place certificate into NEW
        add certificate to metadata
        sign metadata with NEW key

    - Else (NEW is full):
        If OLD is full:
            ERROR: We already have 2 certificates in rotation
        Move NEW → OLD
        Insert new certificate into NEW
        add certificate to metadata
    """

    new_exists = file_exists(NEW_CERT_PATH)
    old_exists = file_exists(OLD_CERT_PATH)

    # CASE 1: NEW is empty → first certificate ever
    if not new_exists:
        # put certificate in NEW folder
        os.makedirs(CERT_DIR_NEW, exist_ok=True)
        create_key_and_certificate(NEW_CERT_PATH, NEW_KEY_PATH, NEW_CSR_PATH)

        # add certificate to metadata
        add_certificate_to_metadata(METADATA_PATH, NEW_CERT_PATH)

        # sign metadata with NEW
        sign_metadata(METADATA_PATH, NEW_KEY_PATH, NEW_CERT_PATH)
        return

    # CASE 2: NEW exists → rotation is happening
    if old_exists:
        # we already have NEW + OLD → cannot add a third one
        raise Exception("Rotation error: both NEW and OLD certificates are already present")

    # Move NEW → OLD
    os.makedirs(CERT_DIR_OLD, exist_ok=True)
    os.system(f"mv {NEW_CERT_PATH} {OLD_CERT_PATH}")
    os.system(f"mv {NEW_KEY_PATH} {OLD_KEY_PATH}")
    os.system(f"mv {NEW_CSR_PATH} {OLD_CSR_PATH}")

    # Insert new certificate into NEW
    create_key_and_certificate(NEW_CERT_PATH, NEW_KEY_PATH, NEW_CSR_PATH)

    # Add certificate to metadata
    add_certificate_to_metadata(METADATA_PATH, NEW_CERT_PATH)

    # Sign again with OLD (still valid): the metadata has been modified
    
    # Remove signature
    remove_signature_from_metadata(METADATA_PATH)
    
    # Re-sign using OLD
    sign_metadata(METADATA_PATH, OLD_KEY_PATH, OLD_CERT_PATH)


def remove_expired_certificate():
    """
    Remove the OLD certificate when it expires.

    Logic:
    - We can remove OLD only if NEW and OLD are both present.
    - After removal:
        remove signature
        re-sign using NEW
    """

    new_exists = file_exists(NEW_CERT_PATH)
    old_exists = file_exists(OLD_CERT_PATH)

    if not (new_exists and old_exists):
        raise Exception("Rotation error: cannot remove OLD – rotation state invalid")

    # Remove OLD certificate from metadata
    remove_certificate_from_metadata(METADATA_PATH, OLD_CERT_PATH)

    # Delete OLD directory contents
    if file_exists(OLD_CERT_PATH):
        os.remove(OLD_CERT_PATH)
    if file_exists(OLD_KEY_PATH):
        os.remove(OLD_KEY_PATH)
    if file_exists(OLD_CSR_PATH):
        os.remove(OLD_CSR_PATH)

    # Remove signature
    remove_signature_from_metadata(METADATA_PATH)

    # Re-sign using NEW
    sign_metadata(METADATA_PATH, NEW_KEY_PATH, NEW_CERT_PATH)



# === OPTIONAL: STATE CHECKER ==================================================

def get_rotation_state() -> str:
    """
    Returns the rotation state:
    - 'EMPTY'
    - 'NEW_ONLY'
    - 'NEW_AND_OLD'
    """
    new_exists = file_exists(NEW_CERT_PATH)
    old_exists = file_exists(OLD_CERT_PATH)

    if not new_exists and not old_exists:
        return "EMPTY"
    if new_exists and not old_exists:
        return "NEW_ONLY"
    if new_exists and old_exists:
        return "NEW_AND_OLD"

    return "INVALID"

if __name__ == "__main__":
    state = get_rotation_state()
    print("=== Certificate Rotation Manager ===")
    print(f"Current rotation state: {state}")
    print("====================================")

    # Test
    print("What point are you at?")
    print("1: Start or next to expiration date")
    print("2: Certificate expired")
    print("3: Restart (clean metadata and certs folders)")

    choice = input("Enter choice (1/2/3): ").strip()
    if choice == "1":
        add_new_certificate()
        print("New certificate added to rotation.")
    elif choice == "2":
        remove_expired_certificate()
        print("Expired certificate removed from rotation.")
    elif choice == "3":
        # Restart logic can be implemented here
        run(f"rm -rf {CERT_DIR_OLD} {CERT_DIR_NEW}", shell=True)
        run(f"cp {METADATA_CLEAN_PATH} {METADATA_PATH}", shell=True)
    else:
        print("Invalid choice.")