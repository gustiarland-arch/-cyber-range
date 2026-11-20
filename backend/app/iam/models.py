"""IAM domain: users, roles, permissions, sessions, API tokens."""
from datetime import datetime

from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy import BigInteger, Boolean, Column, ForeignKey, Index, Integer, JSON, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", BigInteger, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True, index=True),
    Column("granted_at", DATETIME(fsp=6), default=utcnow, nullable=False),
    Column("granted_by", BigInteger, ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    **_TBL,
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True, index=True),
    **_TBL,
)


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    last_login_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    password_changed_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    deleted_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6), index=True)
    # v1.2: single sign-on and TOTP MFA
    auth_source: Mapped[str] = mapped_column(String(16), nullable=False, default="local", server_default="local")  # local | oidc
    oidc_subject: Mapped[str | None] = mapped_column(String(255), unique=True)        # "<issuer>|<sub>"
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text)
    mfa_pending_enc: Mapped[str | None] = mapped_column(Text)
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    mfa_last_counter: Mapped[int | None] = mapped_column(BigInteger)
    mfa_recovery: Mapped[list | None] = mapped_column(JSON)

    @property
    def mfa_enabled(self) -> bool:
        return self.mfa_enabled_at is not None

    roles: Mapped[list["Role"]] = relationship(
        secondary=user_roles,
        primaryjoin=lambda: User.id == user_roles.c.user_id,
        secondaryjoin=lambda: Role.id == user_roles.c.role_id,
        lazy="selectin",
    )


class Role(TimestampMixin, Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    permissions: Mapped[list["Permission"]] = relationship(secondary=role_permissions, lazy="selectin")


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    is_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class UserSession(Base):
    """Refresh-token backed login session. Only token hashes are stored."""

    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_user_active", "user_id", "revoked_at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    last_used_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    revoke_reason: Mapped[str | None] = mapped_column(String(64))
    read_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")   # mobile read-only mode
    auth_method: Mapped[str] = mapped_column(String(16), nullable=False, default="password", server_default="password")  # password | oidc
    mfa: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="")  # space separated permission codes
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    expires_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    revoked_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))


