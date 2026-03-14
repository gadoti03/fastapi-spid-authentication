from database.models.user import User

class UserRepository:

    # GET
    @staticmethod
    def get_by_id(db, user_id):
        return db.query(User).filter(User.id == user_id).first()
    
    @staticmethod
    def get_by_cf(db, cf):
        return db.query(User).filter(User.cf == cf).first()
    
    # CREATE
    @staticmethod
    def create(db, cf):
        new_user = User(
            cf=cf
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user