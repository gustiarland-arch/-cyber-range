"""Red team domain: scenario library, authorised assessments with approval, execution timeline and findings."""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}
ASSESSMENT_STATUSES = ("pending_approval", "approved", "rejected", "queued", "running", "completed", "aborted", "failed", "expired", "cancelled")


class Scenario(Base):
    __tablename__ = "scenarios"
    __table_args__ = (UniqueConstraint("code", name="uq_scenarios_code"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    objective: Mapped[str] = mapped_column(Text, nullable=False, default="")
    difficulty: Mapped[str] = mapped_column(String(16), nullable=False, default="basic")
    steps: Mapped[list] = mapped_column(JSON, nullable=False)  # [{action, title, params, mitre_technique}]
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)


class Assessment(Base):
    __tablename__ = "assessments"
    __table_args__ = (Index("ix_assessments_status", "status"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    scenario_id: Mapped[int] = mapped_column(Integer, ForeignKey("scenarios.id", ondelete="RESTRICT"), nullable=False)
    scenario: Mapped[dict] = mapped_column(JSON, nullable=False)          # frozen copy of the scenario at request time
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="RESTRICT"), nullable=False, index=True)
    instance_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="RESTRICT"), nullable=False)
    runtime_id: Mapped[str] = mapped_column(String(32), nullable=False)    # scope is bound to this exact lab deployment
    attacker_node: Mapped[str] = mapped_column(String(64), nullable=False)
    attacker_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)             # {targets:[{node_key,label,ips}], cidrs:[...]}
    window_start: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending_approval")
    requested_by: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    decided_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    decision_comment: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    abort_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    current_step: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    finished_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)


class AssessmentEvent(Base):
    """Append-only timeline used for live view, replay and the report."""

    __tablename__ = "assessment_events"
    __table_args__ = (_TBL,)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    step_index: Mapped[int | None] = mapped_column(Integer)
    actor_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    message: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    data: Mapped[dict | None] = mapped_column(JSON)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_assessment", "assessment_id", "step_index"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)  # host_up | open_port | http_service | exposure
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target_ip: Mapped[str | None] = mapped_column(String(45))
    port: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict | None] = mapped_column(JSON)
    at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
