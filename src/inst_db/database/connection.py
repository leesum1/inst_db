"""Database connection and session management."""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from inst_db.models.instruction import Base


class DatabaseManager:
    """Manages database connections and sessions."""

    def __init__(self, database_url: str):
        """
        Initialize the database manager.

        Args:
            database_url: SQLAlchemy database URL (e.g., "sqlite:///trace.db")
        """
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            # Enable foreign key constraints for SQLite
            connect_args={"check_same_thread": False} if "sqlite" in database_url else {},
            echo=False,
        )
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
            expire_on_commit=False,
        )

    def init_db(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)

    def drop_db(self):
        """Drop all database tables (USE WITH CAUTION)."""
        Base.metadata.drop_all(bind=self.engine)

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """
        Context manager for database sessions.

        Yields:
            SQLAlchemy Session object
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


# Global database instance placeholder
_db_manager: DatabaseManager | None = None


def init_database(database_url: str) -> DatabaseManager:
    """
    Initialize the global database manager.

    Args:
        database_url: SQLAlchemy database URL

    Returns:
        DatabaseManager instance
    """
    global _db_manager
    _db_manager = DatabaseManager(database_url)
    _db_manager.init_db()
    return _db_manager


def get_db() -> DatabaseManager:
    """
    Get the global database manager instance.

    Returns:
        DatabaseManager instance

    Raises:
        RuntimeError: If database has not been initialized
    """
    if _db_manager is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _db_manager


def get_session() -> Generator[Session, None, None]:
    """Get a database session from the global manager."""
    return get_db().get_session()
