from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database.connection import Base

import secrets

class SamlRequest(Base):
    __tablename__ = "saml_requests"

    id = Column(String, primary_key=True) # SAML Request ID
    request_id = Column(String, unique=True) # SAML Request ID from SPID
    session_id = Column(String, ForeignKey("sessions.id")) # foreign key to Session
    request_type = Column(String) # e.g., "AuthnRequest", "LogoutRequest"
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + datetime.timedelta(minutes=5))
    is_used = Column(Boolean, default=False)