# services/user_service.py
from repositories.user_repository import UserRepository

user_repo = UserRepository()

def get_or_create_user(db, cf):
    user = user_repo.get_by_cf(db, cf)
    if not user:
        user = user_repo.create(db, cf)
    return user