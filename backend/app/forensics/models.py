"""Digital forensics: cases, evidence items (bytes in object storage), acquisition hashes and a hash-chained custody log."""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

EVIDENCE_KINDS = ("file", "disk_image", "memory_image", "pcap", "log_export", "document", "malware_sample", "other")
EVIDENCE_STATUSES = ("collected", "in_analysis", "preserved", "released")
CUSTODY_ACTIONS = ("collected", "accessed", "transferred", "verified", "status_changed", "sealed", "note", "exported")


class ForensicCase(TimestampMixin, Base):
    __tablename__ = "forensic_cases"
    __table_args__ = (Index("ix_forensic_cases_status", "status"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    reference: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)  # CASE-YYYY-NNNN
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")  # open | closed
    classification: Mapped[str] = mapped_column(String(16), nullable=False, default="internal")  # internal | confidential | restricted
    incident_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("incidents.id", ondelete="SET NULL"))
    lead_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    closed_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    closure_note: Mapped[str] = mapped_column(Text, nullable=False, default="")


class Evidence(TimestampMixin, Base):
    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_case", "case_id", "id"), Index("ix_evidence_sha256", "sha256"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    reference: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)  # CASE-YYYY-NNNN/E-NNN
    case_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("forensic_cases.id", ondelete="RESTRICT"), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")  # host/device/system the item came from
    collected_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    collected_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)  # when it was acquired (may precede upload)
    filename: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_key: Mapped[str | None] = mapped_column(String(255))
    sample_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("file_samples.id", ondelete="SET NULL"))
    origin: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # e.g. {"type": "siem_export", "event_ids": [...]}
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="collected")
    custodian_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    is_sealed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    integrity: Mapped[str] = mapped_column(String(16), nullable=False, default="unverified")  # unverified | verified | mismatch
    last_verified_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    custody_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    custody_head: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)


class EvidenceHash(Base):
    __tablename__ = "evidence_hashes"
    __table_args__ = (UniqueConstraint("evidence_id", "algorithm", name="uq_evidence_hashes_algo"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    evidence_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(128), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    computed_by: Mapped[str] = mapped_column(String(64), nullable=False, default="platform")


class CustodyEvent(Base):
    """Append-only custody log. Each entry hashes the previous one (per evidence), so edits or deletions are detectable."""

    __tablename__ = "custody_events"
    __table_args__ = (UniqueConstraint("evidence_id", "seq", name="uq_custody_events_seq"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    evidence_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(64), nullable=False)
    from_custodian: Mapped[str | None] = mapped_column(String(64))
    to_custodian: Mapped[str | None] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    location: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    sha256_observed: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[str | None] = mapped_column(String(16))
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
