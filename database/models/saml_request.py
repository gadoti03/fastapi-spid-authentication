# database/models/saml_request.py
from datetime import datetime, timedelta

from database.connection import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey

class SAMLRequest(Base):
    __tablename__ = "saml_requests"

    id = Column(Integer, primary_key=True) # SAML Request ID
    request_id = Column(String, unique=True) # SAML Request ID from SPID
    session_id = Column(Integer, ForeignKey("sessions.id")) # foreign key to Session
    request_type = Column(String) # e.g. "AuthnRequest", "LogoutRequest" -> to handle with enum
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=5))
    is_used = Column(Boolean, default=False)