from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime
from database.connection import Base

class User(Base): # da modificare
    __tablename__ = "users"
    id = Column(Integer, primary_key=True) # user ID
    cf = Column(String, unique=True) # fiscal code
    # other SPID attributes can be added here as needed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)