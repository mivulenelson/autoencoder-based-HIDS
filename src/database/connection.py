import os
import logging
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("HIDS_Database")

# ── Database URL ──────────────────────────────────────────────────────────────
# SQLite  : "sqlite:///./hids_forensics.db"          (default — zero config)
# Postgres: "postgresql://user:pass@localhost/hids"  (set in .env for production)
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./hids_forensics.db")

_IS_SQLITE = DATABASE_URL.startswith("sqlite")


# ── Engine factory ────────────────────────────────────────────────────────────
def _build_engine():
    if _IS_SQLITE:
        # SQLite requires check_same_thread=False for multi-threaded FastAPI/PySide6 use
        eng = create_engine(
            DATABASE_URL,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        # Enforce foreign-key constraints in SQLite (off by default)
        @event.listens_for(eng, "connect")
        def _set_sqlite_pragma(dbapi_conn, _record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")   # WAL = better concurrency
            cursor.close()

        logger.info(f"SQLite engine created: {DATABASE_URL}")
        return eng

    else:
        
        eng = create_engine(
            DATABASE_URL,
            pool_size=10,          # base pool size
            max_overflow=20,       # extra connections allowed under load
            pool_pre_ping=True,    # test connections before use (handles idle drops)
            pool_timeout=30,       # seconds to wait for a connection before raising
            pool_recycle=1800,     # recycle connections every 30 min (avoids stale TCP)
            echo=False,
        )
        logger.info("SQLite engine created.")
        return eng


engine = _build_engine()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# Column definitions must be valid for BOTH SQLite and PostgreSQL syntax —
# kept intentionally simple (no FKs, no complex defaults) so a single
# ALTER TABLE statement works on either backend without branching per-engine.
_NEW_ALERT_COLUMNS = [
    ("source_port",  "INTEGER"),
    ("dest_port",    "INTEGER"),
    ("is_encrypted", "BOOLEAN DEFAULT FALSE NOT NULL" if not _IS_SQLITE
                      else "BOOLEAN DEFAULT 0 NOT NULL"),
]


def _run_lightweight_migrations() -> None:
    """
    Adds any of _NEW_ALERT_COLUMNS to the existing `alerts` table that are
    not already present. Safe to call on every startup:
      - No-op if the table doesn't exist yet (create_tables() will create
        it fresh with the full current schema, including these columns).
      - No-op per-column if that column already exists.
      - Never touches existing rows or drops anything.
    """
    inspector = inspect(engine)

    if "alerts" not in inspector.get_table_names():
        return   # Fresh database — create_all() already produces the full schema

    existing_cols = {col["name"] for col in inspector.get_columns("alerts")}

    with engine.begin() as conn:
        for col_name, col_def in _NEW_ALERT_COLUMNS:
            if col_name in existing_cols:
                continue
            try:
                conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_def}"))
                logger.info(f"Migration: added column 'alerts.{col_name}' ({col_def})")
            except Exception as exc:               
                logger.error(f"Migration failed for column 'alerts.{col_name}': {exc}")


# ── Schema bootstrap ──────────────────────────────────────────────────────────
def create_tables() -> None:
    """
    Creates all ORM-defined tables that do not yet exist in the database,
    then runs lightweight additive migrations for any columns introduced
    on an already-existing table (see module docstring).

    Safe to call on every startup — SQLAlchemy uses CREATE TABLE IF NOT EXISTS
    semantics for new tables, and _run_lightweight_migrations() is itself
    idempotent for column additions.

    For anything beyond additive columns (renames, type changes, drops),
    use Alembic instead — this function intentionally stays minimal.
    """
    from src.database.models import Base
    Base.metadata.create_all(bind=engine)
    _run_lightweight_migrations()
    logger.info("Database schema verified / created / migrated.")


# ── Session dependency ────────────────────────────────────────────────────────
def get_db():
    """
    FastAPI / PySide6 dependency that yields a SQLAlchemy Session and
    guarantees it is closed after the request completes (success or error).

    Usage in FastAPI:
        @router.get("/alerts")
        async def get_alerts(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()