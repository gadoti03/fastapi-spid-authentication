from settings import settings

from fastapi import HTTPException
from fastapi.responses import FileResponse

from spid.exceptions import MetadataNotFoundError, SessionError

import os

from sqlalchemy.orm import Session
from database.models import Session as DBSess

from spid.authn_request import generate_authn_request, render_saml_form

from spid.slo_handler import generate_logout_request
from spid.utils import get_key_path, get_cert_path, sign_xml, encode_b64, get_field_in_xml, parse_query, verify_saml_status

from spid.utils import get_idp_url

from crud.saml_request import create_saml_request, use_saml_request

from spid.acs_handler import verify_saml_signature as verify_saml_signature_acs, verify_saml_status, extract_spid_attributes

from spid.slo_handler import verify_saml_signature as verify_saml_signature_slo

from crud.session import get_idp_id_by_id, get_or_create_session_by_session_id, invalidate_session_by_id, update_session_with_spid_info, set_idp_id_by_session_id, get_session_by_session_id
from crud.user import create_user, get_user_by_cf, create_or_get_user

from spid.exceptions import SpidConfigError, SpidSignatureError, SpidValidationError, SpidBusinessRuleError, SpidInternalError

METADATA_FILE = settings.METADATA_FILE

def get_spid_metadata() -> FileResponse:
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/xml")
    else:
        raise MetadataNotFoundError("Metadata file not found")

def initiate_authn_request(db: Session, idp: str, db_session: DBSess, relay_state: str):

    # get idp url
    idp_url = get_idp_url(idp, "single_sign_on_service", "HTTP-POST")

    # print("IDP URL:", idp_url + " for idp: " + idp)

    db_session = set_idp_id_by_session_id(db, db_session.session_id, idp) # aggiorno la sessione con l'idp scelto dall'utente
    if not db_session:
        raise SpidInternalError("Session not found or expired for session_id: " + db_session.session_id)
    
    # generate the AuthnRequest XML
    xml, request_id = generate_authn_request(idp_url)
    
    # save the SAML request in the database
    create_saml_request(db, request_id, db_session.id, "AuthnRequest")
    
    # sign the AuthnRequest XML 
    xml = sign_xml(xml_str = xml, key_path = get_key_path(), cert_path = get_cert_path(), after_tag="Issuer")
    
    # base64 encode the signed AuthnRequest XML
    saml_request = encode_b64(xml)

    # render HTML con form auto-submit
    return render_saml_form(idp_url, saml_request, relay_state)

def handle_authn_response(decoded_xml: bytes, db: Session):

    # verify signature
    if not verify_saml_signature_acs(decoded_xml):
        raise SpidSignatureError("Invalid SAML signature")
    
    # verify status
    if not verify_saml_status(decoded_xml):
        raise SpidValidationError("Invalid SAML status")
    
    # get RequestID
    request_id = get_field_in_xml(decoded_xml, "InResponseTo")
    if not request_id:
        raise SpidValidationError("InResponseTo not found in SAMLResponse")

    # verify that the SAML response corresponds to a valid SAML request in the database
    saml_request = use_saml_request(db, request_id)
    if not saml_request:
        raise SpidBusinessRuleError("No matching SAML request found for InResponseTo: " + request_id)
    
    # get SessionIndex
    sessionIndex = get_field_in_xml(decoded_xml, "SessionIndex")
    if not sessionIndex:
        raise SpidValidationError("SessionIndex not found in SAMLResponse")
    
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
    
    # create or get user in the database
    user = create_or_get_user(db, cf)

    # update session (using session_id from saml_request)
    session = update_session_with_spid_info(db, saml_request.session_id, sessionIndex, user.id)
    if not session:
        raise SpidInternalError("Session not found or expired for session_id: " + saml_request.session_id)
    
    return session.session_id

def initiate_logout_request( db: Session, db_session: DBSess, relay_state: str):

    # verify session
    if not db_session or not db_session.is_active:
        raise SessionError("Session not found or expired for spid-logout for session_id: " + db_session.session_id)
    
    # invalidate session in the database (set is_active to False)
    invalidate_session_by_id(db, db_session.id)
    
    # get idp_url
    idp_id = get_idp_id_by_id(db, db_session.id)
    url_slo = get_idp_url(idp_id, "single_logout_service", "HTTP-Redirect")

    # generate LogoutRequest
    xml, request_id = generate_logout_request(db_session.session_id, idp_id, url_slo)
    
    # save the SAML request in the database
    create_saml_request(db, request_id, db_session.id, "LogoutRequest")

    # sign the LogoutRequest XML 
    xml = sign_xml(xml_str = xml, key_path = get_key_path(), cert_path = get_cert_path(), after_tag="SessionIndex")
    
    # base64 encode the signed LogoutRequest XML
    saml_request = encode_b64(xml)
    
    # render HTML con form auto-submit
    return render_saml_form(url_slo, saml_request, relay_state)

def handle_logout_response(db: Session, raw_query: str):

    # parse query parameters
    slo_data = parse_query(raw_query)

    decoded_xml = slo_data["decoded_xml"]
    relay_state = slo_data["RelayState"]
    sig_alg = slo_data["SigAlg"]
    signature = slo_data["Signature"]
    query_to_verify = slo_data["query_to_verify"]

    if not verify_saml_signature_slo(query_to_verify, signature, sig_alg, decoded_xml):
        raise SpidSignatureError("Invalid SAML signature in LogoutResponse")
    
    # verify status
    if not verify_saml_status(decoded_xml):
        raise SpidValidationError("Invalid SAML status in LogoutResponse")
    
    # get RequestID
    request_id = get_field_in_xml(decoded_xml, "InResponseTo")
    if not request_id:
        raise SpidValidationError("InResponseTo not found in SAML LogoutResponse")
    
    # verify that the SAML response corresponds to a valid SAML request in the database
    saml_request = use_saml_request(db, request_id)
    if not saml_request:
        raise SpidBusinessRuleError("No matching SAML request found for InResponseTo: " + request_id)
    
    return relay_state