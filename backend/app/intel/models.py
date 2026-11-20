"""Threat intelligence: sources (provenance), indicators, relationships and sightings against stored security events."""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

INDICATOR_TYPES = ("ip", "cidr", "domain", "url", "sha256", "sha1", "md5", "email")
SOURCE_KINDS = ("manual", "feed", "demo")
RELATION_KINDS = ("related-to", "resolves-to", "communicates-with", "downloads", "variant-of", "part-of")


class IntelSource(Base):
    __tablename__ = "intel_sources"
    __table_args__ = (UniqueConstraint("name", name="uq_intel_sources_name"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reference_url: Mapped[str | None] = mapped_column(String(512))
    default_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_import_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class Indicator(Base):
    """One observable from one source. The same value from two sources is two rows (separate provenance and confidence)."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("source_id", "type", "value_key", name="uq_indicators_source_value"),
        Index("ix_indicators_lookup", "type", "value_key", "is_active"),
        Index("ix_indicators_sighted", "last_sighted_at"),
        _TBL,
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_id: Mapped[int] = mapped_column(Integer, ForeignKey("intel_sources.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    value_key: Mapped[str] = mapped_column(String(255), nullable=False)  # normalized value, or sha256 of it when longer than 255
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)  # 0..100
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=2)     # 0..4
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    first_seen: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sightings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_sighted_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    external_id: Mapped[str | None] = mapped_column(String(128))  # e.g. STIX indicator id
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)


class IndicatorRelation(Base):
    __tablename__ = "indicator_relations"
    __table_args__ = (UniqueConstraint("from_id", "to_id", "kind", name="uq_indicator_relations"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    from_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    to_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class Sighting(Base):
    """An indicator observed in a stored security event (live on ingest or by retro-hunt)."""

    __tablename__ = "indicator_sightings"
    __table_args__ = (UniqueConstraint("indicator_id", "event_id", name="uq_sightings"), Index("ix_sightings_time", "seen_at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    indicator_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False)
    field: Mapped[str] = mapped_column(String(32), nullable=False)   # where it matched: src_ip, dst_ip, host, message, raw
    seen_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    via: Mapped[str] = mapped_column(String(16), nullable=False, default="ingest")  # ingest | retrohunt
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


FEED_TYPES = ("misp", "taxii21", "stix_url", "text_url", "csv_url")


class IntelFeed(Base):
    """A scheduled pull of indicators into one intel source. Credentials are never stored: `auth_env` names an
    environment variable (CR_FEED_*) on the worker that holds the API key/token."""

    __tablename__ = "intel_feeds"
    __table_args__ = (UniqueConstraint("source_id", name="uq_intel_feeds_source"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[int] = mapped_column(Integer, ForeignKey("intel_sources.id", ondelete="CASCADE"), nullable=False)
    feed_type: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    collection_id: Mapped[str | None] = mapped_column(String(128))      # TAXII collection
    auth_env: Mapped[str | None] = mapped_column(String(64))            # name of the env var with the secret
    auth_scheme: Mapped[str] = mapped_column(String(16), nullable=False, default="none")  # none | misp | bearer | basic
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cursor: Mapped[str | None] = mapped_column(String(64))              # TAXII added_after / MISP timestamp of last success
    last_run_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    last_status: Mapped[str | None] = mapped_column(String(16))         # ok | error
    last_error: Mapped[str | None] = mapped_column(Text)
    last_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
