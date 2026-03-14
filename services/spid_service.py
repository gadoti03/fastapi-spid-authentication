# services/spid_service.py
from fastapi.responses import FileResponse

from settings import settings

import os

from sqlalchemy.orm import Session
from database.models import Session as DBSess

from spid.authn_request import generate_authn_request, render_saml_form
from spid.acs_handler import verify_saml_signature as verify_saml_signature_acs, verify_saml_status, extract_spid_attributes
from spid.slo_handler import verify_saml_signature as verify_saml_signature_slo, generate_logout_request
from spid.utils import get_key_path, get_cert_path, sign_xml, encode_b64, get_field_in_xml, parse_query, verify_saml_status, get_idp_url
from spid.exceptions import MetadataNotFoundError, SpidConfigError, SpidSignatureError, SpidValidationError, SpidBusinessRuleError, SpidInternalError, SessionError

from repositories.saml_request_repository import SAMLRequestRepository
from repositories.session_repository import SessionRepository

from services.session_service import is_session_valid
from services.user_service import get_or_create_user

METADATA_FILE = settings.METADATA_FILE

def get_spid_metadata() -> FileResponse:
    if os.path.exists(METADATA_FILE):
        return FileResponse(METADATA_FILE, media_type="application/xml")
    else:
        raise MetadataNotFoundError("Metadata file not found")

def initiate_authn_request(db: Session, idp: str, db_session: DBSess, relay_state: str):

    # get idp url
    idp_url = get_idp_url(idp, "single_sign_on_service", "HTTP-POST")

    print("IDP URL:", idp_url + " for idp: " + idp)

    db_session = SessionRepository.set_idp(db, db_session, idp) # update session with idp_id
    if not db_session:
        raise SessionError("Session not found or expired for session_id: " + db_session.session_id)
    
    # generate the AuthnRequest XML
    xml, request_id = generate_authn_request(idp_url)
    
    # save the SAML request in the database
    SAMLRequestRepository.create(db, request_id, db_session.id, "AuthnRequest")
    
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

    # get saml_request from the database
    saml_request = SAMLRequestRepository.get_by_request_id(db, request_id)
    if not saml_request:
        raise SpidValidationError("No matching SAML request found for InResponseTo: " + request_id)

    # verify that the SAML response corresponds to a valid SAML request in the database
    saml_request = SAMLRequestRepository.use_request(db, saml_request)
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
    user = get_or_create_user(db, cf)

    # update session
    db_session = SessionRepository.get_by_id(db, saml_request.session_id)
    if not db_session:
        raise SessionError("Session not found or expired for session_id: " + saml_request.session_id)
    
    db_session = SessionRepository.set_spid_info(db, db_session, sessionIndex, user.id)
    if not db_session:
        raise SessionError("Session not found or expired for session_id: " + saml_request.session_id)
    
    return db_session.session_id

def initiate_logout_request( db: Session, db_session: DBSess, relay_state: str):

    # verify session
    if not is_session_valid(db_session):
        raise SessionError("Session not found or expired for spid-logout for session_id: " + db_session.session_id)
    
    # get idp_url
    idp_id = db_session.idp_id
    url_slo = get_idp_url(idp_id, "single_logout_service", "HTTP-Redirect")

    # generate LogoutRequest
    xml, request_id = generate_logout_request(db_session.session_id, idp_id, url_slo)
    
    # save the SAML request in the database
    SAMLRequestRepository.create(db, request_id, db_session.id, "LogoutRequest")

    # sign the LogoutRequest XML 
    xml = sign_xml(xml_str = xml, key_path = get_key_path(), cert_path = get_cert_path(), after_tag="SessionIndex")
    
    # base64 encode the signed LogoutRequest XML
    saml_request = encode_b64(xml)

    # invalidate session in the database (set is_active to False)
    SessionRepository.invalidate(db, db_session)
    
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
    saml_request = SAMLRequestRepository.use_request(db, request_id)
    if not saml_request:
        raise SpidValidationError("No matching SAML request found for InResponseTo: " + request_id)
    
    return relay_state