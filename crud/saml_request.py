import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session
from database.models import Session as DBSess
from database.models import SamlRequest

def create_saml_request(db: Session, request_id: str, session_id: str, request_type: str):
    new_request = SamlRequest(
        id=str(uuid.uuid4()),
        request_id=request_id,
        session_id=session_id,
        request_type=request_type,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        is_used=False
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)
    return new_request

def use_saml_request(db: Session, request_id: str):
    saml_request = db.query(SamlRequest).filter(SamlRequest.request_id == request_id).first()
    if saml_request and not saml_request.is_used and saml_request.expires_at > datetime.utcnow():
        saml_request.is_used = True
        db.commit()
        return saml_request
    return None

def delete_expired_requests(db: Session):
    now = datetime.utcnow()
    db.query(SamlRequest).filter(SamlRequest.expires_at < now).delete()
    db.commit()