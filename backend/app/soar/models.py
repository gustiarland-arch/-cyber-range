"""Light SOAR: response playbooks made only of catalogued, reversible steps. Every containment step waits for a human."""
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}
RUN_STATUSES = ("running", "awaiting_approval", "completed", "rejected", "failed", "cancelled")
RUN_OPEN = ("running", "awaiting_approval")


class Playbook(Base):
    __tablename__ = "soar_playbooks"
    __table_args__ = (_TBL,)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    trigger: Mapped[dict] = mapped_column(JSON, nullable=False)   # {"mode": "manual"|"auto", "rule_codes": [...], "min_severity": 0-4}
    steps: Mapped[list] = mapped_column(JSON, nullable=False)     # [{"action": "...", "params": {...}}]
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    runs_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)


class PlaybookRun(Base):
    __tablename__ = "soar_runs"
    __table_args__ = (Index("ix_soar_runs_status", "status", "created_at"), Index("ix_soar_runs_alert", "alert_id"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(Integer, ForeignKey("soar_playbooks.id", ondelete="RESTRICT"), nullable=False)
    alert_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")  # manual | auto
    current_step: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    steps: Mapped[list] = mapped_column(JSON, nullable=False)     # snapshot of the playbook steps with per-step results
    facts: Mapped[dict] = mapped_column(JSON, nullable=False)     # observables collected by earlier steps
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    error: Mapped[str | None] = mapped_column(Text)
