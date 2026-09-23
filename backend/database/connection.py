from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from .models import Base, User, Project, Scan, Vulnerability, Asset, ToolResult, Report, ChatHistory
from app.config import settings

DATABASE_URL = settings.database_url

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)

if "sqlite" in DATABASE_URL:
    # Phase 10.3 parallel scheduler: multiple worker sessions write to the same
    # SQLite file concurrently. WAL allows a reader + one writer without
    # "database is locked"; busy_timeout makes contentious writes wait instead
    # of failing immediately.
    from sqlalchemy import event

    def _sqlite_pragmas(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    event.listen(engine, "connect", _sqlite_pragmas)
else:
    engine = create_engine(DATABASE_URL, connect_args={})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_schema(engine=engine):
    """Fails loudly when the database has not been migrated.

    Production startup assumes the schema is managed by Alembic migrations.
    This function never creates, drops, or alters tables.
    """
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    expected = set(Base.metadata.tables.keys())
    missing = expected - existing
    if missing:
        raise RuntimeError(
            "Database schema is missing table(s): {}."
            " Run 'alembic upgrade head' before starting the application.".format(", ".join(sorted(missing)))
        )

def seed_defaults(db=None):
    """Idempotently seeds the bootstrap admin user from configuration.

    No rows are created unless ``ADMIN_EMAIL`` and ``ADMIN_PASSWORD`` are both
    explicitly set in the environment (see app.config.settings.admin_enabled),
    so there is never an implicit, hardcoded identity.  Existing production
    user data is never touched.

    This does not create or drop any table; it only inserts rows when they
    do not exist yet. Safe to call on every startup.
    """
    if not settings.admin_enabled:
        return
    owns_session = db is None
    if owns_session:
        db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == settings.admin_email).first()
        if admin is None:
            from app.core.security import hash_password

            admin = User(
                id="admin-" + settings.admin_email,
                email=settings.admin_email,
                password_hash=hash_password(settings.admin_password),
                role="admin",
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
    except Exception:
        db.rollback()
        raise
    finally:
        if owns_session:
            db.close()