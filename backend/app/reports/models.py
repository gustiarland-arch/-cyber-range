"""Generated reports. The rendered file lives in object storage; MySQL keeps who/what/when, the data sources used,
the SHA-256 of the file and its object key."""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}
KINDS = ("incident", "assessment", "lab_run", "vulnerability", "evidence", "training")
FORMATS = ("pdf", "csv")
STATUSES = ("queued", "running", "completed", "failed")


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_creator", "created_by", "created_at"), Index("ix_reports_kind", "kind", "created_at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    fmt: Mapped[str] = mapped_column(String(8), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    created_by: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # human-readable data sources used
    row_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    object_key: Mapped[str | None] = mapped_column(String(255))
    sha256: Mapped[str | None] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class BackupRun(Base):
    """Recorded by scripts/backup.sh (via the CLI) so the UI can show backup status. The backup itself lives outside
    the database it protects."""
    __tablename__ = "backup_runs"
    __table_args__ = (Index("ix_backup_runs_at", "finished_at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(String(64), nullable=False)  # backup directory name (UTC timestamp)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="backup")  # backup | restore | verify
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # ok | failed
    started_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    components: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # [{name, file, size, sha256}]
    total_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    schema_revision: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    host: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
