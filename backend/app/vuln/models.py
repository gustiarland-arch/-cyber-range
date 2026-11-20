"""Vulnerability management: catalogue, authorised lab scan jobs, de-duplicated findings and remediation tracking."""
from datetime import date, datetime

from sqlalchemy import JSON, BigInteger, Boolean, Date, ForeignKey, Index, Integer, Numeric, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

FINDING_STATUSES = ("open", "in_remediation", "fixed_pending_verification", "resolved", "false_positive", "risk_accepted")
JOB_STATUSES = ("queued", "running", "completed", "failed", "aborted")
TASK_STATUSES = ("open", "in_progress", "done", "cancelled")


class Vulnerability(TimestampMixin, Base):
    """A catalogue entry: what a check (or an analyst) can report. Builtin entries come from the safe check catalogue."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("code", name="uq_vulnerabilities_code"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=2)  # 0 info .. 4 critical
    cvss: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cves: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cwe: Mapped[str | None] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="configuration")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    detection: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")  # check | version | manual
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (Index("ix_scan_jobs_lab", "lab_id", "id"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    profile: Mapped[str] = mapped_column(String(24), nullable=False, default="standard")
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False)
    instance_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="SET NULL"))
    runtime_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_node: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_ip: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)  # {"targets": [{node_key,label,ips}], "lab_name"}
    ports: Mapped[list] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    progress: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    log: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    abort_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    finished_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))


class ScanFinding(TimestampMixin, Base):
    """One vulnerability on one lab asset/port. Re-detections update the same row (dedup key below)."""

    __tablename__ = "scan_findings"
    __table_args__ = (
        UniqueConstraint("lab_id", "node_key", "vulnerability_id", "port", name="uq_scan_findings_asset_vuln"),
        Index("ix_scan_findings_status", "status", "severity"),
        _TBL,
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False)
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False)
    node_key: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_label: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    ip: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 0 = host-level
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=2)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="scan")  # scan | manual
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # what was observed (banner, headers, path status)
    first_job_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    last_job_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    first_seen: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    times_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    resolved_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    status_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    risk_accepted_until: Mapped[date | None] = mapped_column(Date)
    owner_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))


class FindingEvent(Base):
    __tablename__ = "scan_finding_events"
    __table_args__ = (Index("ix_scan_finding_events_finding", "finding_id", "id"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("scan_findings.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(String(1024), nullable=False)
    job_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    actor_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class RemediationTask(TimestampMixin, Base):
    __tablename__ = "remediation_tasks"
    __table_args__ = (Index("ix_remediation_tasks_finding", "finding_id"), Index("ix_remediation_tasks_assignee", "assignee_id", "status"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("scan_findings.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    assignee_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    due_date: Mapped[date | None] = mapped_column(Date)
    completed_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
