# services/saml_request_service.py
from datetime import datetime, timedelta

from repositories.session_repository import SessionRepository

saml_request_repo = SessionRepository()

def is_saml_request_valid(saml_request):
    return saml_request and not saml_request.is_used and saml_request.created_at > datetime.utcnow() - timedelta(minutes=5)