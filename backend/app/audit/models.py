"""Append-only, hash-chained audit log."""
from datetime import datetime

from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy import JSON, BigInteger, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_occurred_at", "occurred_at"),
        Index("ix_audit_logs_actor_time", "actor_user_id", "occurred_at"),
        Index("ix_audit_logs_action_time", "action", "occurred_at"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        _TBL,
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(255), nullable=False, default="anonymous")
    action: Mapped[str] = mapped_column(String(96), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)  # success | failure | denied
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(36))
    details: Mapped[dict | None] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class AuditChainHead(Base):
    """Single row (id=1) locked FOR UPDATE to serialise hash-chain appends."""

    __tablename__ = "audit_chain_head"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    last_id: Mapped[int | None] = mapped_column(BigInteger)
