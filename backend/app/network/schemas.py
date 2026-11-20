"""Canonical topology document — the single format for the API, the 2D editor, the 3D view and JSON/YAML import/export."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.network.models import LINK_KINDS, NODE_TYPES, ZONE_KINDS

KEY = r"^[A-Za-z0-9_.:-]{1,64}$"
MAX_NODES, MAX_LINKS, MAX_SUBNETS, MAX_ZONES = 500, 2000, 256, 64


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Point(_Strict):
    x: float = Field(ge=-100_000, le=100_000)
    y: float = Field(ge=-100_000, le=100_000)


class Size(_Strict):
    w: float = Field(ge=80, le=20_000)
    h: float = Field(ge=60, le=20_000)


class ZoneDoc(_Strict):
    key: str = Field(pattern=KEY)
    name: str = Field(min_length=1, max_length=128)
    kind: Literal[ZONE_KINDS] = "internal"  # type: ignore[valid-type]
    color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    position: Point = Point(x=0, y=0)
    size: Size = Size(w=480, h=320)


class SubnetDoc(_Strict):
    key: str = Field(pattern=KEY)
    name: str = Field(min_length=1, max_length=128)
    cidr: str = Field(min_length=1, max_length=43)
    gateway: str | None = Field(default=None, max_length=39)
    vlan: int | None = Field(default=None, ge=1, le=4094)
    zone: str | None = Field(default=None, pattern=KEY)


class InterfaceDoc(_Strict):
    name: str = Field(pattern=r"^[A-Za-z0-9_./:-]{1,32}$")
    subnet: str | None = Field(default=None, pattern=KEY)
    ip: str | None = Field(default=None, max_length=39)

    @field_validator("ip", "subnet", mode="before")
    @classmethod
    def _blank(cls, v):
        return v or None


class NodeDoc(_Strict):
    key: str = Field(pattern=KEY)
    type: Literal[NODE_TYPES]  # type: ignore[valid-type]
    label: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=253, pattern=r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
    os: str | None = Field(default=None, max_length=64)
    zone: str | None = Field(default=None, pattern=KEY)
    group: str | None = Field(default=None, max_length=64)
    properties: dict = Field(default_factory=dict)
    position: Point = Point(x=0, y=0)
    elevation: float | None = Field(default=None, ge=-1000, le=1000)
    interfaces: list[InterfaceDoc] = Field(default_factory=list, max_length=16)

    @field_validator("hostname", "os", "zone", "group", mode="before")
    @classmethod
    def _blank(cls, v):
        return v or None

    @field_validator("properties")
    @classmethod
    def _props_size(cls, v: dict) -> dict:
        import json
        if len(json.dumps(v, default=str)) > 8192:
            raise ValueError("properties must be at most 8 KB of JSON")
        return v


class LinkDoc(_Strict):
    key: str = Field(pattern=KEY)
    source: str = Field(pattern=KEY)
    target: str = Field(pattern=KEY)
    label: str | None = Field(default=None, max_length=128)
    kind: Literal[LINK_KINDS] = "ethernet"  # type: ignore[valid-type]
    bandwidth_mbps: int | None = Field(default=None, ge=1, le=1_000_000)


class TopologyDoc(_Strict):
    format: Literal["cyber-range/topology"] = "cyber-range/topology"
    schema_version: Literal[1] = 1
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4000)
    zones: list[ZoneDoc] = Field(default_factory=list, max_length=MAX_ZONES)
    subnets: list[SubnetDoc] = Field(default_factory=list, max_length=MAX_SUBNETS)
    nodes: list[NodeDoc] = Field(default_factory=list, max_length=MAX_NODES)
    links: list[LinkDoc] = Field(default_factory=list, max_length=MAX_LINKS)


class NetworkCreate(_Strict):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4000)
    visibility: Literal["private", "shared"] = "private"
    template: str | None = Field(default=None, max_length=64)


class NetworkMetaUpdate(_Strict):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=4000)
    visibility: Literal["private", "shared"] | None = None


class TopologySave(_Strict):
    expected_version: int = Field(ge=1)
    topology: TopologyDoc


class ImportRequest(_Strict):
    format: Literal["json", "yaml"]
    content: str = Field(min_length=2, max_length=1_000_000)
    name: str | None = Field(default=None, max_length=128)
    visibility: Literal["private", "shared"] = "private"


class Issue(BaseModel):
    severity: Literal["error", "warning"]
    code: str
    message: str
    ref: dict | None = None  # {"node": key} | {"link": key} | {"subnet": key} | {"zone": key}


class NetworkSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    owner_id: int
    owner: str | None = None
    visibility: str
    version: int
    validation_status: str
    error_count: int
    warning_count: int
    node_count: int = 0
    link_count: int = 0
    created_at: datetime
    updated_at: datetime
    can_edit: bool = False


class NetworkDetail(NetworkSummary):
    topology: TopologyDoc
    issues: list[Issue]
