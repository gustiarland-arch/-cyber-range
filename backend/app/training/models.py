"""Practice: CTF challenges with hints and hashed flags (or graded Sigma/YARA rules), missions with
platform-verified objectives, and the score ledger."""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME, MEDIUMTEXT
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

CATEGORIES = ("web", "network", "forensics", "crypto", "malware", "blue-team", "osint", "misc")
LEVELS = ("beginner", "intermediate", "advanced")
OBJECTIVE_KINDS = ("answer", "challenge", "vuln_finding", "assessment", "sensor", "alert_closed", "incident_closed")
CHALLENGE_KINDS = ("flag", "sigma", "yara")  # sigma/yara: the learner submits a rule that is graded automatically


class Challenge(TimestampMixin, Base):
    __tablename__ = "challenges"
    __table_args__ = (UniqueConstraint("slug", name="uq_challenges_slug"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(16), nullable=False, default="beginner")
    points: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    description: Mapped[str] = mapped_column(MEDIUMTEXT, nullable=False)
    flag_format: Mapped[str] = mapped_column(String(64), nullable=False, default="CR{...}")
    flag_salt: Mapped[str] = mapped_column(String(32), nullable=False)
    flag_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256(salt + normalised flag); plaintext never stored
    case_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lab_template: Mapped[str | None] = mapped_column(String(64))  # optional isolated lab to practise in
    attachments: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # [{name, key, size, sha256}]
    is_published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(8), nullable=False, default="flag", server_default="flag")
    grader: Mapped[dict | None] = mapped_column(JSON)  # server-side grading data for rule challenges; never returned by the API


class Hint(Base):
    __tablename__ = "challenge_hints"
    __table_args__ = (Index("ix_challenge_hints_challenge", "challenge_id", "position"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    challenge_id: Mapped[int] = mapped_column(Integer, ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    cost: Mapped[int] = mapped_column(Integer, nullable=False, default=10)


class HintUnlock(Base):
    __tablename__ = "hint_unlocks"
    __table_args__ = (UniqueConstraint("user_id", "hint_id", name="uq_hint_unlocks_user_hint"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    hint_id: Mapped[int] = mapped_column(Integer, ForeignKey("challenge_hints.id", ondelete="CASCADE"), nullable=False)
    unlocked_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class Submission(Base):
    """Every flag attempt. The submitted value is stored only as a hash (wrong guesses can contain sensitive text)."""

    __tablename__ = "submissions"
    __table_args__ = (Index("ix_submissions_user_chal", "user_id", "challenge_id", "submitted_at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    challenge_id: Mapped[int] = mapped_column(Integer, ForeignKey("challenges.id", ondelete="CASCADE"), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    is_correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class Mission(TimestampMixin, Base):
    __tablename__ = "missions"
    __table_args__ = (UniqueConstraint("slug", name="uq_missions_slug"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    briefing: Mapped[str] = mapped_column(MEDIUMTEXT, nullable=False)
    difficulty: Mapped[str] = mapped_column(String(16), nullable=False, default="beginner")
    lab_template: Mapped[str | None] = mapped_column(String(64))
    is_published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))


class Objective(Base):
    __tablename__ = "mission_objectives"
    __table_args__ = (Index("ix_mission_objectives_mission", "mission_id", "position"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mission_id: Mapped[int] = mapped_column(Integer, ForeignKey("missions.id", ondelete="CASCADE"), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # answer: {"salt","hash","case_sensitive"} · challenge: {"slug"} · vuln_finding: {"code"} · assessment: {"scenario"}
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    points: Mapped[int] = mapped_column(Integer, nullable=False, default=25)
    hint: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ScoreEvent(Base):
    """Append-only score ledger. One row per scoring action; uniqueness prevents double scoring."""

    __tablename__ = "score_events"
    __table_args__ = (UniqueConstraint("user_id", "source", "ref_id", name="uq_score_events_once"), Index("ix_score_events_at", "at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # challenge | objective
    ref_id: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(16), nullable=False, default="misc")
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    first_blood: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


# ------------------------------------------------------------------ v1.3 instructor-led classes


