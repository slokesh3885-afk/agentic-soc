import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# SQLite database file path (located in backend/ directory)
DATABASE_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "agentic_soc.db"))
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

# Engine with thread check disabled for SQLite in multi-threaded FastAPI workers
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency that provides a database session and safely closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
