from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database.connection import Base

import secrets

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True) # session ID
    user_id = Column(Integer, ForeignKey("users.id")) # foreign key to User
    spid_session_index = Column(String, unique=True) # SPID SessionIndex
    created_at = Column(DateTime, default=datetime.utcnow) 
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + datetime.timedelta(days=1))
    is_active = Column(Boolean, default=True)