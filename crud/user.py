import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database.models import User

def create_user(db: Session, cf: str):
    new_user = User(
        id=str(uuid.uuid4()),
        cf=cf,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_user_by_cf(db: Session, cf: str):
    return db.query(User).filter(User.cf == cf).first()