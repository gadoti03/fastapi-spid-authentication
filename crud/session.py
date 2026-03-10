import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database.models import Session as DBSess
from database.models import User

def get_session(db: Session, session_id: str):
    session = db.query(DBSess).filter(DBSess.id == session_id).first()
    return session

# create a new session and return it
def create_session(db: Session):
    new_session = DBSess(
        id=str(uuid.uuid4()),
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=1),
        spid_session_index=None,
        is_active=True
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return new_session

def get_or_create_session(db: Session, session_id: str):
    session = get_session(db, session_id)
    if session and session.is_active and session.expires_at > datetime.utcnow():
        return session
    else:
        return create_session(db)

def update_session_with_spid_info(db: Session, session_id: str, spid_session_index: str, codice_fiscale: str):
    session = db.query(DBSess).filter(DBSess.id == session_id).first()
    user = db.query(User).filter(User.cf == codice_fiscale).first()
    if session:
        session.spid_session_index = spid_session_index
        session.user_id = user.id
        db.commit()
        db.refresh(session)
        return session
    return None