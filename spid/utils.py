from settings import settings

from settings import settings
import os

def get_key_and_cert():
    """
    Return (cert_content, key_content) following the SPID logic:

    - If neither NEW nor OLD have certificates → error
    - If both NEW and OLD exist → use OLD
    - If OLD does not exist → use NEW
    """

    NEW_CERT_PATH = os.path.join(settings.CERT_DIR_NEW, "crt.pem")
    NEW_KEY_PATH  = os.path.join(settings.CERT_DIR_NEW, "key.pem")

    OLD_CERT_PATH = os.path.join(settings.CERT_DIR_OLD, "crt.pem")
    OLD_KEY_PATH  = os.path.join(settings.CERT_DIR_OLD, "key.pem")

    new_exists = os.path.isfile(NEW_CERT_PATH) and os.path.isfile(NEW_KEY_PATH)
    old_exists = os.path.isfile(OLD_CERT_PATH) and os.path.isfile(OLD_KEY_PATH)

    # No certificate → error
    if not new_exists and not old_exists:
        raise Exception("Rotation error: no certificates found in NEW or OLD directories.")

    # If both exist → OLD is the “stable” certificate
    if new_exists and old_exists:
        with open(OLD_CERT_PATH, "r") as fcert, open(OLD_KEY_PATH, "r") as fkey:
            return fcert.read(), fkey.read()

    # If OLD does not exist → use NEW (initial phase)
    if new_exists:
        with open(NEW_CERT_PATH, "r") as fcert, open(NEW_KEY_PATH, "r") as fkey:
            return fcert.read(), fkey.read()

    # Corrupted state: OLD partially present
    raise Exception("Invalid rotation state: OLD certificate directory is incomplete.")
