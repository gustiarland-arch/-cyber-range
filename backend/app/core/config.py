"""Application configuration loaded from environment variables (see .env.example)."""
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CR_", extra="ignore")

    app_name: str = "CYBER RANGE"
    environment: str = Field(default="development", pattern="^(development|test|production)$")
    debug: bool = False
    api_prefix: str = "/api/v1"

    # MySQL 8.4 LTS is the only supported relational database.
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "cyber_range"
    mysql_password: SecretStr = SecretStr("")
    mysql_database: str = "cyber_range"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_recycle: int = 1800

    redis_url: str = "redis://127.0.0.1:6379/0"

    jwt_secret: SecretStr = SecretStr("")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    cookie_secure: bool = False

    login_rate_limit: int = 10  # attempts per window per IP
    login_rate_window_seconds: int = 300
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    cors_origins: list[str] = ["http://localhost:5173"]
    trust_proxy_headers: bool = False  # set true only behind the bundled reverse proxy

    celery_broker_url: str | None = None  # defaults to redis_url

    # Object storage for samples, evidence and exports (metadata stays in MySQL).
    storage_adapter: str = Field(default="filesystem", pattern="^(filesystem|minio)$")
    storage_dir: str = "/var/lib/cyber-range/storage"
    storage_bucket: str = "cyber-range"
    minio_url: str = "minio:9000"
    minio_access_key: str = ""
    minio_secret_key: SecretStr = SecretStr("")
    minio_secure: bool = False

    # Malware sandbox adapter (dynamic analysis happens ONLY in an external, disposable, isolated sandbox).
    sandbox_provider: str = Field(default="none", pattern="^(none|cape)$")
    sandbox_url: str = ""
    sandbox_token: SecretStr = SecretStr("")
    sandbox_timeout_seconds: int = 120

    sla_targets: str = ""                   # "critical=15/240;high=30/480" minutes to acknowledge/resolve; empty = built-in defaults

    # Local edition: one operator, reachable only from this computer (see app/iam/router.py).
    local_operator: str = "operator"
    local_allowed_hosts: str = "localhost,127.0.0.1,::1"
    # Optional second factor for the local session: when set, POST /auth/local also needs header X-Local-Token with this
    # value. It stops other programs on the same computer (which can reach 127.0.0.1) from opening an operator session.
    local_access_token: SecretStr = SecretStr("")
    kit_vagrant_boxes: str = "default=bento/ubuntu-24.04"
    # Lab Kit option "DC Windows": Vagrant box with Windows Server (Evaluation) for the office lab domain controller
    kit_windows_dc_box: str = "gusztavvargadr/windows-server-2022-standard"
    # Lab Kit option "Windows 11" per employee PC: Vagrant box with Windows 11 (Evaluation), joined to the Windows DC
    kit_windows_pc_box: str = "gusztavvargadr/windows-11"

    @field_validator("local_access_token")
    @classmethod
    def _local_token_len(cls, v: SecretStr) -> SecretStr:
        t = v.get_secret_value()
        if t and (len(t) < 24 or not t.replace("-", "").replace("_", "").isalnum()):
            raise ValueError("CR_LOCAL_ACCESS_TOKEN must be empty or at least 24 characters of A-Z, a-z, 0-9, '-' or '_'")
        return v

    @field_validator("jwt_secret")
    @classmethod
    def _secret_len(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("CR_JWT_SECRET must be set and at least 32 characters long")
        return v

    @property
    def database_url(self) -> str:
        from urllib.parse import quote_plus

        pwd = quote_plus(self.mysql_password.get_secret_value())
        return (
            f"mysql+pymysql://{self.mysql_user}:{pwd}@{self.mysql_host}:{self.mysql_port}/"
            f"{self.mysql_database}?charset=utf8mb4"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
