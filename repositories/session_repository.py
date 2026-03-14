# repositories/session_repository.py
from database.models.session import Session

class SessionRepository:

    # GET
    @staticmethod
    def get_by_id(db, session_id):
        return db.query(Session).filter(Session.id == session_id).first()
    
    @staticmethod
    def get_by_session_id(db, session_id):
        return db.query(Session).filter(Session.session_id == session_id).first()

    @staticmethod
    def get_by_spid_session_index(db, spid_session_index):
        return db.query(Session).filter(Session.spid_session_index == spid_session_index).first()
    
    # CREATE
    @staticmethod
    def create(db):
        s = Session()
        db.add(s)
        db.commit()
        db.refresh(s)
        return s
    
    # UPDATE
    @staticmethod
    def set_idp(db, session: Session, idp_id: str):
        if session:
            session.idp_id = idp_id
            db.commit()
            db.refresh(session)
        return session
    
    @staticmethod
    def set_spid_info(db, session: Session, spid_session_index: str, user_id: int):
        if session:
            session.spid_session_index = spid_session_index
            session.user_id = user_id
            db.commit()
            db.refresh(session)
        return session
    
    @staticmethod
    def invalidate(db, session: Session):
        if session:
            session.is_active = False
            db.commit()
            db.refresh(session)
        return session