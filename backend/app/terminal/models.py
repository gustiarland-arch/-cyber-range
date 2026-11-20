"""Brokered terminal sessions into lab containers (never the host)."""
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}
STATUSES = ("issued", "active", "closed", "expired", "denied")
OPEN = ("issued", "active")


class TerminalSession(Base):
    __tablename__ = "terminal_sessions"
    __table_args__ = (Index("ix_terminal_sessions_user_status", "user_id", "status"), Index("ix_terminal_sessions_lab", "lab_id"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False)
    instance_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="CASCADE"), nullable=False)
    node_key: Mapped[str] = mapped_column(String(64), nullable=False)
    container_name: Mapped[str] = mapped_column(String(128), nullable=False)
    docker_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="issued")
    ticket_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    issued_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    ended_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    end_reason: Mapped[str | None] = mapped_column(String(64))
    closed_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    bytes_in: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    transcript_key: Mapped[str | None] = mapped_column(String(255))
    transcript_sha256: Mapped[str | None] = mapped_column(String(64))
    client_ip: Mapped[str | None] = mapped_column(String(64))
