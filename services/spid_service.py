from settings import settings

from fastapi import HTTPException
from fastapi.responses import FileResponse

from spid.exceptions import MetadataNotFoundError

import os

from sqlalchemy.orm import Session
from database.models import Session as DBSess

from spid.authn_request import generate_authn_request, get_idp_url, render_saml_form

from spid.utils import get_key_path, get_cert_path, sign_xml, encode_b64, get_field_in_xml, parse_query, verify_saml_status

from crud.saml_request import create_saml_request, use_saml_request

from spid.acs_handler import verify_saml_signature as verify_saml_signature_acs, verify_saml_status, extract_spid_attributes
from crud.session import get_or_create_session, update_session_with_spid_info
from crud.user import create_user, get_user_by_cf

from spid.exceptions import SpidConfigError, SpidSignatureError, SpidValidationError, SpidBusinessRuleError, SpidInternalError

METADATA_FILE = settings.METADATA_FILE

def get_spid_metadata() -> FileResponse:
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/xml")
    else:
        raise MetadataNotFoundError("Metadata file not found")

def initiate_authn_request(idp: str, db: Session, db_session: DBSess, relay_state: str):

    # get idp url
    idp_url = get_idp_url(idp)
    
    # generate the AuthnRequest XML
    xml, request_id = generate_authn_request(idp_url)
    
    # save the SAML request in the database
    # imp: gli passo la sessione aggiornata
    # mi servirà poi per associare la risposta SAML alla sessione utente, e quindi all'utente stesso
    create_saml_request(db, request_id, db_session.id, "AuthnRequest")

    # print("Request ID /login:", request_id)
    
    # sign the AuthnRequest XML 
    xml = sign_xml(xml_str = xml, key_path = get_key_path(), cert_path = get_cert_path(), after_tag="Issuer")
    
    # base64 encode the signed AuthnRequest XML
    saml_request = encode_b64(xml)

    # render HTML con form auto-submit
    return render_saml_form(idp_url, saml_request, relay_state)

def handle_authn_response(decoded_xml: bytes, db: Session, relay_state: str):

    # verify signature
    if not verify_saml_signature_acs(decoded_xml):
        raise SpidSignatureError("Invalid SAML signature")
    
    # verify status
    if not verify_saml_status(decoded_xml):
        raise SpidValidationError("Invalid SAML status")
    
    # get SessionIndex
    sessionIndex = get_field_in_xml(decoded_xml, "SessionIndex")
    if not sessionIndex:
        raise SpidValidationError("SessionIndex not found in SAMLResponse")
    
    
    
    # get RequestID
    request_id = get_field_in_xml(decoded_xml, "InResponseTo")
    if not request_id:
        raise SpidValidationError("InResponseTo not found in SAMLResponse")
    
    # get user attributes
    user_attrs = extract_spid_attributes(decoded_xml)
    if not user_attrs:
        raise SpidValidationError("No user attributes found in SAMLResponse")
    
    cf = user_attrs.get("codice_fiscale")
    if not cf:
        raise SpidValidationError("codice_fiscale not found in SAMLResponse attributes")
    
    redidence = user_attrs.get("residenza")
    if not redidence:
        raise SpidValidationError("residenza not found in SAMLResponse attributes")
    
    # verify business rules
    if redidence != settings.REQUIRED_RESIDENCE:
        raise SpidBusinessRuleError("User does not meet residence requirements")