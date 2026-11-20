from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

class RoleBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    code: str
    name: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    username: str
    full_name: str
    is_active: bool
    locked_until: datetime | None
    last_login_at: datetime | None
    created_at: datetime
    roles: list[RoleBrief]
    mfa_enabled: bool = False
    auth_source: str = "local"


class MeOut(BaseModel):
    user: UserOut
    permissions: list[str]
    read_only: bool = False
    mfa_enrollment_required: bool = False
    auth_method: str = "local"


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut
    permissions: list[str]
    read_only: bool = False
    mfa_enrollment_required: bool = False


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
