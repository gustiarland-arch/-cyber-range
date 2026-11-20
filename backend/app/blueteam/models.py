"""Blue team / SOC domain: log sources, normalized security events, detection rules, alerts, incidents."""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

SOURCE_KINDS = ("zeek", "suricata", "wazuh", "syslog", "json", "platform")
SEVERITIES = ("info", "low", "medium", "high", "critical")  # stored as 0..4
CATEGORIES = ("network", "ids", "auth", "host", "dns", "http", "file", "platform", "other")
ALERT_STATUSES = ("new", "acknowledged", "in_progress", "resolved", "false_positive")
ALERT_OPEN = ("new", "acknowledged", "in_progress")
INCIDENT_STATUSES = ("open", "investigating", "contained", "eradicated", "recovered", "closed")


class LogSource(Base):
    __tablename__ = "log_sources"
    __table_args__ = (UniqueConstraint("name", name="uq_log_sources_name"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    lab_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="SET NULL"))
    key_prefix: Mapped[str | None] = mapped_column(String(12))   # first chars of the ingest key, for identification only
    key_hash: Mapped[str | None] = mapped_column(String(64), unique=True)  # sha256 of the ingest key; the key itself is never stored
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cursor: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)  # platform source: last forwarded audit id
    last_event_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    events_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class SecurityEvent(Base):
    """One normalized event. (source_id, event_uid) is the idempotency key: re-sending a batch never duplicates."""

    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("source_id", "event_uid", name="uq_security_events_source_uid"),
        Index("ix_security_events_time", "occurred_at"),
        Index("ix_security_events_cat_time", "category", "occurred_at"),
        Index("ix_security_events_src_ip", "src_ip", "occurred_at"),
        Index("ix_security_events_dst_ip", "dst_ip", "occurred_at"),
        Index("ix_security_events_sev", "severity", "occurred_at"),
        _TBL,
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_id: Mapped[int] = mapped_column(Integer, ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False)
    event_uid: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    dataset: Mapped[str] = mapped_column(String(32), nullable=False)       # e.g. zeek.conn, suricata.alert
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str | None] = mapped_column(String(64))                  # e.g. allowed, blocked, failure, success, REJ
    outcome: Mapped[str | None] = mapped_column(String(16))
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    src_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    host: Mapped[str | None] = mapped_column(String(255))
    user: Mapped[str | None] = mapped_column(String(128))
    signature: Mapped[str | None] = mapped_column(String(255))
    signature_id: Mapped[str | None] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    raw: Mapped[dict] = mapped_column(JSON, nullable=False)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (UniqueConstraint("code", name="uq_detection_rules_code"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=2)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="match")  # match | threshold
    conditions: Mapped[list] = mapped_column(JSON, nullable=False)   # [{field, op, value}] all must hold
    threshold: Mapped[dict | None] = mapped_column(JSON)              # {count, window_seconds, group_by, distinct?}
    group_by: Mapped[str | None] = mapped_column(String(32))          # alert grouping field for match rules
    mitre_tactic: Mapped[str | None] = mapped_column(String(64))
    mitre_technique: Mapped[str | None] = mapped_column(String(32))
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    origin: Mapped[str] = mapped_column(String(16), nullable=False, default="manual", server_default="manual")  # builtin | manual | sigma
    source_text: Mapped[str | None] = mapped_column(Text)   # original rule source (e.g. Sigma YAML) for imported rules
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    hits: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_sev", "status", "severity"), Index("ix_alerts_rule_group", "rule_id", "group_key", "status"),
                      Index("ix_alerts_last_seen", "last_seen"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("detection_rules.id", ondelete="RESTRICT"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    group_key: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    first_seen: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assignee_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    incident_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    resolution: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    closed_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))

    rule: Mapped[DetectionRule] = relationship(lazy="joined")


class AlertEvent(Base):
    __tablename__ = "alert_events"
    __table_args__ = (_TBL,)
    alert_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True, index=True)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_status", "status", "severity"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    owner_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_by: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))


class IncidentEntry(Base):
    """Incident timeline: notes, status changes, linked alerts. Append-only."""

    __tablename__ = "incident_entries"
    __table_args__ = (_TBL,)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    author_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(24), nullable=False)  # note | status | alert_linked | assigned | created
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    data: Mapped[dict | None] = mapped_column(JSON)
