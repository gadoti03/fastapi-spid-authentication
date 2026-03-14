# database/models/user.py
from datetime import datetime

from database.connection import Base
from sqlalchemy import Column, Integer, String, DateTime

class User(Base): # da modificare
    __tablename__ = "users"
    id = Column(Integer, primary_key=True) # user ID
    cf = Column(String, unique=True) # fiscal code
    # other SPID attributes can be added here as needed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)