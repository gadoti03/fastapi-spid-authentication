# services/session_service.py
from datetime import datetime

from repositories.session_repository import SessionRepository

session_repo = SessionRepository()

def is_session_valid(session):
    return session and session.is_active and session.expires_at > datetime.utcnow()

# get or create
def get_or_create_session_by_id(db, session_id: int):
    session = session_repo.get_by_id(db, session_id)
    if not is_session_valid(session):
        session = session_repo.create(db)
    return session

def get_or_create_session_by_session_id(db, session_id: str):
    session = session_repo.get_by_session_id(db, session_id)
    if not is_session_valid(session):
        session = session_repo.create(db)
    return session

# idp
def get_idp_by_id(db, session_id: int):
    session = session_repo.get_by_id(db, session_id)
    if is_session_valid(session):
        return session.idp_id
    return None

def get_idp_by_session_id(db, session_id: str):
    session = session_repo.get_by_session_id(db, session_id)
    if is_session_valid(session):
        return session.idp_id
    return None

# user
def get_id_user_by_id(db, session_id: int):
    session = session_repo.get_by_id(db, session_id)
    if is_session_valid(session) and session.user_id:
        return session.user_id
    return None

def get_id_user_by_session_id(db, session_id: str):
    session = session_repo.get_by_session_id(db, session_id)
    if is_session_valid(session) and session.user_id:
        return session.user_id
    return None

