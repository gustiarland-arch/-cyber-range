"""SQLAlchemy 2 engine/session for MySQL 8.4 (InnoDB, utf8mb4, UTC)."""
from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy import MetaData, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.core.config import get_settings

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    """Naive UTC datetime (MySQL DATETIME has no tz; all stored values are UTC)."""
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)
    __table_args__ = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)


_settings = get_settings()
engine = create_engine(
    _settings.database_url,
    pool_size=_settings.db_pool_size,
    max_overflow=_settings.db_max_overflow,
    pool_recycle=_settings.db_pool_recycle,
    pool_pre_ping=True,
    future=True,
)


@event.listens_for(engine, "connect")
def _set_session_tz(dbapi_conn, _record):  # pragma: no cover - driver hook
    with dbapi_conn.cursor() as cur:
        cur.execute("SET time_zone = '+00:00'")
        cur.execute("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'")


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def on_commit(db: Session, fn) -> None:
    """Run fn() once the session's ROOT transaction commits (savepoint releases do not count); dropped on rollback."""
    from sqlalchemy import event as sa_event
    hooks = db.info.setdefault("on_commit", [])
    hooks.append(fn)
    if db.info.get("on_commit_listening"):
        return
    db.info["on_commit_listening"] = True

    def _after_commit(session):
        if session.in_nested_transaction():
            return  # a SAVEPOINT was released; wait for the real commit
        pending, session.info["on_commit"] = session.info.get("on_commit", []), []
        for f in pending:
            try:
                f()
            except Exception:  # noqa: BLE001
                from app.core.logging import log
                log.exception("on_commit_hook_failed")

    def _after_rollback(session):
        if not session.in_nested_transaction():
            session.info["on_commit"] = []

    sa_event.listen(db, "after_commit", _after_commit)
    sa_event.listen(db, "after_soft_rollback", lambda s, prev: _after_rollback(s))
