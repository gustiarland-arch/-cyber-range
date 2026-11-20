"""Network domain: topologies (labs_networks), zones, subnets, nodes, interfaces, links, 2D/3D positions.

One data model feeds both the 2D topology editor and the 3D visualisation.
Every child row carries a client-stable `key` (unique per network) so saves are upserts, not rewrites.
"""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

NODE_TYPES = ("server", "workstation", "router", "switch", "firewall", "database", "internet", "vm", "container", "sensor")
ZONE_KINDS = ("internet", "dmz", "internal", "management", "lab", "restricted")
LINK_KINDS = ("ethernet", "fiber", "wireless", "vpn", "virtual")


class LabNetwork(Base):
    __tablename__ = "labs_networks"
    __table_args__ = (
        Index("ix_labs_networks_visibility", "visibility", "deleted_at"),
        _TBL,
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False, default="private")  # private | shared
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    validation_status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")  # valid | warnings | invalid
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)
    updated_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    deleted_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))

    zones: Mapped[list["NetworkZone"]] = relationship(cascade="all, delete-orphan", lazy="selectin", order_by="NetworkZone.id")
    subnets: Mapped[list["Subnet"]] = relationship(cascade="all, delete-orphan", lazy="selectin", order_by="Subnet.id")
    nodes: Mapped[list["NetworkNode"]] = relationship(cascade="all, delete-orphan", lazy="selectin", order_by="NetworkNode.id")
    links: Mapped[list["NetworkLink"]] = relationship(cascade="all, delete-orphan", lazy="selectin", order_by="NetworkLink.id")


class NetworkZone(Base):
    __tablename__ = "network_zones"
    __table_args__ = (UniqueConstraint("network_id", "key", name="uq_network_zones_key"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    network_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs_networks.id", ondelete="CASCADE"), nullable=False)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="internal")
    color: Mapped[str | None] = mapped_column(String(16))
    x: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    y: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    width: Mapped[float] = mapped_column(Float, nullable=False, default=480)
    height: Mapped[float] = mapped_column(Float, nullable=False, default=320)


class Subnet(Base):
    __tablename__ = "subnets"
    __table_args__ = (UniqueConstraint("network_id", "key", name="uq_subnets_key"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    network_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs_networks.id", ondelete="CASCADE"), nullable=False)
    zone_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("network_zones.id", ondelete="SET NULL"), index=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    cidr: Mapped[str] = mapped_column(String(43), nullable=False)
    gateway: Mapped[str | None] = mapped_column(String(39))
    vlan_id: Mapped[int | None] = mapped_column(Integer)


class NetworkNode(Base):
    __tablename__ = "network_nodes"
    __table_args__ = (UniqueConstraint("network_id", "key", name="uq_network_nodes_key"), Index("ix_network_nodes_type", "network_id", "type"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    network_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs_networks.id", ondelete="CASCADE"), nullable=False)
    zone_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("network_zones.id", ondelete="SET NULL"), index=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(253))
    os: Mapped[str | None] = mapped_column(String(64))
    group_name: Mapped[str | None] = mapped_column(String(64))
    properties: Mapped[dict | None] = mapped_column(JSON)  # flexible metadata: services, ports, cpu, ram, notes

    interfaces: Mapped[list["NodeInterface"]] = relationship(cascade="all, delete-orphan", lazy="selectin", order_by="NodeInterface.id")
    position: Mapped["NodePosition | None"] = relationship(cascade="all, delete-orphan", lazy="selectin", uselist=False)


class NodeInterface(Base):
    __tablename__ = "node_interfaces"
    __table_args__ = (UniqueConstraint("node_id", "name", name="uq_node_interfaces_name"), Index("ix_node_interfaces_ip", "subnet_id", "ip_address"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("network_nodes.id", ondelete="CASCADE"), nullable=False)
    subnet_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("subnets.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(32), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(39))


class NodePosition(Base):
    """Layout coordinates. x/y drive the 2D editor and the 3D ground plane; z is an optional 3D elevation override."""

    __tablename__ = "node_positions"
    node_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("network_nodes.id", ondelete="CASCADE"), primary_key=True)
    x: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    y: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    z: Mapped[float | None] = mapped_column(Float)


class NetworkLink(Base):
    __tablename__ = "network_links"
    __table_args__ = (UniqueConstraint("network_id", "key", name="uq_network_links_key"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    network_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs_networks.id", ondelete="CASCADE"), nullable=False)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_node_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("network_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_node_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("network_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    label: Mapped[str | None] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="ethernet")
    bandwidth_mbps: Mapped[int | None] = mapped_column(Integer)
