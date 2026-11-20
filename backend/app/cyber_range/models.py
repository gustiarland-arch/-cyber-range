"""Cyber range domain: image allowlist, labs, lab instances, containers, VMs, runtime networks, snapshots, events."""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, utcnow

_TBL = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_0900_ai_ci"}

INSTANCE_ACTIVE = ("provisioning", "running", "stopping", "stopped", "starting", "resetting", "snapshotting", "restoring", "destroying")
INSTANCE_STATES = INSTANCE_ACTIVE + ("destroyed", "failed")


class LabImage(Base):
    """Allowlisted container images. Labs may only run images listed and enabled here."""

    __tablename__ = "images"
    __table_args__ = (UniqueConstraint("reference", name="uq_images_reference"), _TBL)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    reference: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. alpine:3.20
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    node_types: Mapped[list] = mapped_column(JSON, nullable=False)  # node types this image may back
    command: Mapped[list | None] = mapped_column(JSON)  # override CMD (e.g. keep-alive for base images)
    tmpfs: Mapped[list | None] = mapped_column(JSON)    # writable tmpfs paths
    cap_add: Mapped[list | None] = mapped_column(JSON)  # minimal capabilities the image needs (all others dropped)
    default_cpus: Mapped[float] = mapped_column(nullable=False, default=0.25)
    default_memory_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=128)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class Lab(Base):
    __tablename__ = "labs"
    __table_args__ = (Index("ix_labs_owner", "owner_id", "deleted_at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    network_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs_networks.id", ondelete="RESTRICT"), nullable=False, index=True)
    network_version: Mapped[int] = mapped_column(Integer, nullable=False)
    topology: Mapped[dict] = mapped_column(JSON, nullable=False)  # frozen topology document (reproducible deploys)
    plan: Mapped[dict] = mapped_column(JSON, nullable=False)      # computed deployment plan (networks, containers, skipped)
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, onupdate=utcnow, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))

    instances: Mapped[list["LabInstance"]] = relationship(lazy="selectin", order_by="LabInstance.id.desc()")


class LabInstance(Base):
    __tablename__ = "lab_instances"
    __table_args__ = (Index("ix_lab_instances_status", "status"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True)
    runtime_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)  # short id used in docker names
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="provisioning")
    desired: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    stopped_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    destroyed_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))

    containers: Mapped[list["LabContainer"]] = relationship(lazy="selectin", cascade="all, delete-orphan", order_by="LabContainer.id")
    networks: Mapped[list["LabRuntimeNetwork"]] = relationship(lazy="selectin", cascade="all, delete-orphan", order_by="LabRuntimeNetwork.id")
    vms: Mapped[list["VirtualMachine"]] = relationship(lazy="selectin", cascade="all, delete-orphan")


class LabRuntimeNetwork(Base):
    __tablename__ = "lab_runtime_networks"
    __table_args__ = (UniqueConstraint("instance_id", "subnet_key", name="uq_lab_runtime_networks_subnet"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    instance_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="CASCADE"), nullable=False)
    subnet_key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    cidr: Mapped[str] = mapped_column(String(43), nullable=False, index=True)
    docker_id: Mapped[str | None] = mapped_column(String(80))
    internal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class LabContainer(Base):
    __tablename__ = "containers"
    __table_args__ = (UniqueConstraint("instance_id", "node_key", name="uq_containers_node"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    instance_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="CASCADE"), nullable=False)
    node_key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    image_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    docker_id: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    addresses: Mapped[dict | None] = mapped_column(JSON)  # {subnet_key: ip}
    cpus: Mapped[float] = mapped_column(nullable=False)
    memory_mb: Mapped[int] = mapped_column(Integer, nullable=False)


class VirtualMachine(Base):
    """VM-backed nodes (KVM/Proxmox adapters). Recorded even when the host cannot run them."""

    __tablename__ = "virtual_machines"
    __table_args__ = (UniqueConstraint("instance_id", "node_key", name="uq_virtual_machines_node"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    instance_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="CASCADE"), nullable=False)
    node_key: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)  # libvirt | proxmox | fake
    status: Mapped[str] = mapped_column(String(16), nullable=False)    # pending | running | stopped | missing | failed
    detail: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(String(80))               # provider-side name (cr-<runtime>-<node>)
    template: Mapped[str | None] = mapped_column(String(64))
    vcpus: Mapped[int | None] = mapped_column(Integer)
    memory_mb: Mapped[int | None] = mapped_column(Integer)
    nics: Mapped[list | None] = mapped_column(JSON)                    # [{"subnet_key", "ip", "mac"}] (IP is configured by the guest, e.g. cloud-init)


class Snapshot(Base):
    __tablename__ = "snapshots"
    __table_args__ = (_TBL,)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True)
    instance_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="creating")  # creating | ready | failed | deleted
    images: Mapped[dict | None] = mapped_column(JSON)  # {node_key: image_id}
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)


class LabEvent(Base):
    """Lifecycle timeline for a lab (operational log; security-relevant actions also go to audit_logs)."""

    __tablename__ = "lab_events"
    __table_args__ = (Index("ix_lab_events_lab_time", "lab_id", "occurred_at"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False)
    instance_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="SET NULL"))
    occurred_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    level: Mapped[str] = mapped_column(String(8), nullable=False, default="info")  # info | warn | error
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    data: Mapped[dict | None] = mapped_column(JSON)


SENSOR_KINDS = ("zeek", "suricata")


class LabSensor(Base):
    """A passive network sensor (Zeek or Suricata) capturing one isolated lab network; its logs feed the SOC."""

    __tablename__ = "lab_sensors"
    __table_args__ = (UniqueConstraint("instance_id", "kind", "subnet_key", name="uq_lab_sensors_net"), _TBL)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    lab_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("labs.id", ondelete="CASCADE"), nullable=False, index=True)
    instance_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("lab_instances.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    subnet_key: Mapped[str] = mapped_column(String(64), nullable=False)
    interface: Mapped[str] = mapped_column(String(32), nullable=False)
    image_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")  # pending | starting | running | stopped | failed
    docker_id: Mapped[str | None] = mapped_column(String(80))
    log_source_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("log_sources.id", ondelete="SET NULL"))
    offsets: Mapped[dict | None] = mapped_column(JSON)          # {log file: bytes already ingested}
    events_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6), default=utcnow, nullable=False)
    stopped_at: Mapped[datetime | None] = mapped_column(DATETIME(fsp=6))
