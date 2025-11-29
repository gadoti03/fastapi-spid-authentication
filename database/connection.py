from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from decouple import config

DATABASE_URL = config("DATABASE_URL")

# bind the engine to the database URL
engine = create_engine(DATABASE_URL, echo=True, future=True)
# echo = True: log SQL statements on console
# future = True: use the new features of SQLAlchemy 2.0

# create a configured "Session" class
#   through a Session I will interact with the database
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
# autocommit=False: commit to database only if I run
#   db.commit()
# autoflush=False: flush to database only if I run
#   db.flush()

# create a Base class for the models to inherit from
class Base(DeclarativeBase):
    pass

# dependency to get a session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# import all models here for Alembic - at the end to avoid circular imports
import database.models