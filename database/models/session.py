# database/models/session.py
from datetime import datetime, timedelta

import uuid

from database.connection import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True) # session ID
    session_id = Column(String, unique=True, default=lambda: str(uuid.uuid4())) # random session ID for the user
    user_id = Column(Integer, ForeignKey("users.id"), default=None) # foreign key to User
    spid_session_index = Column(String, unique=True, default=None) # SPID SessionIndex
    idp_id = Column(String, default=None) # IDP identifier
    created_at = Column(DateTime, default=datetime.utcnow) 
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=1))
    is_active = Column(Boolean, default=True)