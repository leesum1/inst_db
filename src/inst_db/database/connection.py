"""Database connection and session management."""

from contextlib import contextmanager
from typing import Generator, Optional
import sqlite3

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from inst_db.models.instruction import Base


class DatabaseManager:
    """Manages database connections and sessions."""

    def __init__(self, database_url: str, use_in_memory: bool = False):
        """
        Initialize the database manager.

        Args:
            database_url: SQLAlchemy database URL (e.g., "sqlite:///trace.db")
            use_in_memory: If True, use an in-memory SQLite database
        """
        self.database_url = database_url
        self.use_in_memory = use_in_memory
        self.file_path: Optional[str] = None

        engine_url = database_url
        connect_args = {}
        engine_kwargs = {}

        if database_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
            if use_in_memory:
                engine_url = "sqlite+pysqlite:///:memory:"
                engine_kwargs["poolclass"] = StaticPool
            else:
                self.file_path = self._extract_sqlite_path(database_url)

        self.engine = create_engine(
            engine_url,
            connect_args=connect_args,
            echo=False,
            **engine_kwargs,
        )

        if database_url.startswith("sqlite"):
            event.listen(self.engine, "connect", self._apply_sqlite_pragmas)

        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
            expire_on_commit=False,
        )

    @staticmethod
    def _extract_sqlite_path(database_url: str) -> Optional[str]:
        if database_url.startswith("sqlite:////"):
            return database_url.replace("sqlite:////", "/", 1)
        if database_url.startswith("sqlite:///"):
            return database_url.replace("sqlite:///", "", 1)
        return None

    @staticmethod
    def _apply_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=MEMORY")
        cursor.execute("PRAGMA synchronous=OFF")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()

    def init_db(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
        self._ensure_schema_compatibility()

    def _ensure_schema_compatibility(self) -> None:
        """Apply lightweight schema compatibility updates for SQLite databases."""
        if not self.database_url.startswith("sqlite"):
            return

        inspector = inspect(self.engine)
        table_names = inspector.get_table_names()
        if "instructions" not in table_names:
            return

        instruction_columns = {
            column["name"] for column in inspector.get_columns("instructions")
        }
        has_core_id = "core_id" in instruction_columns
        has_virtual_pc = "virtual_pc" in instruction_columns
        has_physical_pc = "physical_pc" in instruction_columns
        has_legacy_pc = "pc" in instruction_columns

        if not has_core_id:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE instructions "
                        "ADD COLUMN core_id INTEGER NOT NULL DEFAULT 0"
                    )
                )

        if not has_virtual_pc:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE instructions "
                        "ADD COLUMN virtual_pc VARCHAR(32)"
                    )
                )
                if has_legacy_pc:
                    connection.execute(
                        text(
                            "UPDATE instructions SET virtual_pc = pc "
                            "WHERE virtual_pc IS NULL"
                        )
                    )

        if not has_physical_pc:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE instructions "
                        "ADD COLUMN physical_pc VARCHAR(32)"
                    )
                )
                connection.execute(
                    text(
                        "UPDATE instructions SET physical_pc = COALESCE(virtual_pc, pc) "
                        "WHERE physical_pc IS NULL"
                    )
                )

        with self.engine.begin() as connection:
            if has_legacy_pc:
                connection.execute(
                    text(
                        "UPDATE instructions "
                        "SET virtual_pc = COALESCE(virtual_pc, pc) "
                        "WHERE virtual_pc IS NULL"
                    )
                )
                connection.execute(
                    text(
                        "UPDATE instructions "
                        "SET physical_pc = COALESCE(physical_pc, virtual_pc, pc) "
                        "WHERE physical_pc IS NULL"
                    )
                )
            else:
                connection.execute(
                    text(
                        "UPDATE instructions "
                        "SET physical_pc = COALESCE(physical_pc, virtual_pc) "
                        "WHERE physical_pc IS NULL"
                    )
                )

        instruction_indexes = {
            index["name"] for index in inspector.get_indexes("instructions")
        }
        if "ix_instructions_core_id" not in instruction_indexes:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS "
                        "ix_instructions_core_id ON instructions (core_id)"
                    )
                )
        if "ix_instructions_virtual_pc" not in instruction_indexes:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS "
                        "ix_instructions_virtual_pc ON instructions (virtual_pc)"
                    )
                )
        if "ix_instructions_physical_pc" not in instruction_indexes:
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS "
                        "ix_instructions_physical_pc ON instructions (physical_pc)"
                    )
                )

    def drop_db(self):
        """Drop all database tables (USE WITH CAUTION)."""
        Base.metadata.drop_all(bind=self.engine)

    def save_to_file(self, file_path: str) -> None:
        """Persist the in-memory database to a SQLite file."""
        if not self.use_in_memory:
            raise ValueError("save_to_file() is only supported for in-memory databases")

        if not file_path:
            raise ValueError("file_path is required")

        raw_connection = self.engine.raw_connection()
        try:
            memory_conn = raw_connection.connection
            disk_conn = sqlite3.connect(file_path)
            try:
                memory_conn.backup(disk_conn)
            finally:
                disk_conn.close()
        finally:
            raw_connection.close()

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


def init_database(database_url: str, use_in_memory: bool = False) -> DatabaseManager:
    """
    Initialize the global database manager.

    Args:
        database_url: SQLAlchemy database URL
        use_in_memory: If True, use an in-memory SQLite database

    Returns:
        DatabaseManager instance
    """
    global _db_manager
    _db_manager = DatabaseManager(database_url, use_in_memory=use_in_memory)
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
