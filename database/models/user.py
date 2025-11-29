from sqlalchemy import Column, Integer, String
from database.connection import Base

class User(Base): # da modificare
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String)
