import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database.models import Session as DBSess
from database.models import User

from crud.user import create_or_get_user

# get not expired session by session_id
def get_session_by_session_id(db: Session, session_id: str):
    session = db.query(DBSess).filter(
        DBSess.session_id == session_id,
        DBSess.expires_at > datetime.utcnow()).first()
    return session

def get_session_by_id(db: Session, session_id: int):
    session = db.query(DBSess).filter(
        DBSess.id == session_id,
        DBSess.expires_at > datetime.utcnow()).first()
    return session

# create a new session and return it
def create_session(db: Session):
    new_session = DBSess(
        session_id=str(uuid.uuid4()),
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=1),
        spid_session_index=None,
        is_active=True
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return new_session

def get_or_create_session_by_session_id(db: Session, session_id: str):
    session = get_session_by_session_id(db, session_id)
    if session and session.is_active:
        return session
    else:
        return create_session(db)

def update_session_with_spid_info(db: Session, session_id: int, spid_session_index: str, user_id: int):
    session = get_session_by_id(db, session_id) # get not expired session
    if session:
        session.user_id = user_id
        session.spid_session_index = spid_session_index
        db.commit()
        db.refresh(session)
        return session
    return None