"""Runtime drivers. The API never talks to Docker; only the lab worker (queue `lab`) uses a driver."""
from __future__ import annotations

import os
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

LABEL = "cyber-range.managed"


class DriverError(Exception):
    pass


@dataclass
class ContainerSpec:
    name: str
    image: str
    hostname: str
    labels: dict
    cpus: float
    memory_mb: int
    command: list | None = None
    tmpfs: list = field(default_factory=list)
    cap_add: list = field(default_factory=list)
    ip_forward: bool = False
    attachments: list = field(default_factory=list)  # [{"network": name, "ip": str|None}]
    env: dict = field(default_factory=dict)          # only platform-built office images get lab environment values


@dataclass
class SensorSpec:
    """A passive capture container: host network namespace (to see the lab bridge), only capture capabilities."""
    name: str
    image: str
    labels: dict
    command: list
    cap_add: list
    tmpfs: list = field(default_factory=list)
    entrypoint: list | None = None
    memory_mb: int = 512
    cpus: float = 1.0


def bridge_name(net_id: str) -> str:
    """Linux bridge Docker creates for a user-defined network (needs no Docker connection)."""
    return "br-" + net_id[:12]


class LabDriver(ABC):
    name = "abstract"

    def create_sensor(self, spec: SensorSpec) -> str:
        raise DriverError(f"the {self.name} driver cannot run sensors")

    def read_file(self, cid: str, path: str, offset: int, limit: int) -> bytes:
        raise DriverError(f"the {self.name} driver cannot read sensor logs")

    def bridge_interface(self, net_id: str) -> str:
        return bridge_name(net_id)

    @abstractmethod
    def ensure_image(self, ref: str) -> None: ...
    @abstractmethod
    def create_network(self, name: str, cidr: str, gateway: str, labels: dict) -> str: ...
    @abstractmethod
    def remove_network(self, net_id: str) -> None: ...
    @abstractmethod
    def create_container(self, spec: ContainerSpec) -> str: ...
    @abstractmethod
    def start(self, cid: str) -> None: ...
    @abstractmethod
    def stop(self, cid: str, timeout: int = 5) -> None: ...
    @abstractmethod
    def remove_container(self, cid: str) -> None: ...
    @abstractmethod
    def state(self, cid: str) -> str: ...
    @abstractmethod
    def addresses(self, cid: str) -> dict: ...  # {network_name: ip}
    @abstractmethod
    def commit(self, cid: str, repository: str, tag: str) -> str: ...
    @abstractmethod
    def exec(self, cid: str, argv: list[str], timeout: int = 60) -> tuple[int, str]: ...  # runs inside a lab container only
    @abstractmethod
    def remove_image(self, image_id: str) -> None: ...
    @abstractmethod
    def stats(self, cid: str) -> dict: ...
    @abstractmethod
    def list_managed(self, instance_runtime_id: str) -> dict: ...  # {"containers": [...ids], "networks": [...ids]}


class DockerDriver(LabDriver):
    name = "docker"

    def __init__(self):
        import docker  # imported lazily: the API image never needs a Docker connection
        self.docker = docker
        self.client = docker.from_env(timeout=60)
        self.api = self.client.api

    def ensure_image(self, ref):
        try:
            self.client.images.get(ref)
        except self.docker.errors.ImageNotFound:
            try:
                self.client.images.pull(ref)
            except self.docker.errors.APIError as e:
                hint = (" (a CYBER RANGE office lab image: build it once with "
                        "'docker compose --profile lab-images build', which start.bat/start.sh also do)") if ref.startswith("cyber-range/lab-") else ""
                raise DriverError(f"cannot pull image {ref}: {e.explanation}{hint}") from None

    def create_network(self, name, cidr, gateway, labels):
        ipam = self.docker.types.IPAMConfig(pool_configs=[self.docker.types.IPAMPool(subnet=cidr, gateway=gateway)])
        try:
            net = self.client.networks.create(
                name, driver="bridge", internal=True, ipam=ipam, labels=labels, check_duplicate=True,
                options={"com.docker.network.bridge.enable_ip_masquerade": "false", "com.docker.network.bridge.enable_icc": "true",
                         # the host gets no address on lab bridges: labs cannot reach host services at all
                         "com.docker.network.bridge.inhibit_ipv4": "true"},
            )
        except self.docker.errors.APIError as e:
            raise DriverError(f"network {name} ({cidr}): {e.explanation}") from None
        return net.id

    def remove_network(self, net_id):
        try:
            self.client.networks.get(net_id).remove()
        except self.docker.errors.NotFound:
            pass

    def create_container(self, spec):
        first = spec.attachments[0] if spec.attachments else None
        sysctls = {"net.ipv4.ping_group_range": "0 2147483647"}
        if spec.ip_forward:
            sysctls["net.ipv4.ip_forward"] = "1"
        host_config = self.api.create_host_config(
            network_mode=first["network"] if first else "none",
            # NET_RAW is part of Docker's default set: ICMP ping (busybox/alpine) needs it. Everything else stays dropped.
            cap_drop=["ALL"], cap_add=sorted(set(spec.cap_add or []) | {"NET_RAW"}), security_opt=["no-new-privileges:true"],
            mem_limit=f"{spec.memory_mb}m", memswap_limit=f"{spec.memory_mb}m", nano_cpus=int(spec.cpus * 1e9),
            pids_limit=256, init=True, sysctls=sysctls, privileged=False,
            tmpfs={p: "rw,nosuid,nodev,size=32m" for p in spec.tmpfs},
            log_config={"type": "json-file", "config": {"max-size": "1m", "max-file": "2"}},
            restart_policy={"Name": "no"},
        )
        net_cfg = None
        if first:
            net_cfg = self.api.create_networking_config({first["network"]: self.api.create_endpoint_config(ipv4_address=first["ip"])})
        try:
            c = self.api.create_container(spec.image, command=spec.command, name=spec.name, hostname=spec.hostname,
                                          labels=spec.labels, host_config=host_config, networking_config=net_cfg, detach=True,
                                          environment=spec.env or None)
            for a in spec.attachments[1:]:
                self.api.connect_container_to_network(c["Id"], a["network"], ipv4_address=a["ip"])
        except self.docker.errors.APIError as e:
            raise DriverError(f"container {spec.name}: {e.explanation}") from None
        return c["Id"]

    def start(self, cid):
        try:
            self.api.start(cid)
        except self.docker.errors.APIError as e:
            raise DriverError(f"start {cid[:12]}: {e.explanation}") from None

    def stop(self, cid, timeout=5):
        try:
            self.api.stop(cid, timeout=timeout)
        except self.docker.errors.NotFound:
            pass

    def remove_container(self, cid):
        try:
            self.api.remove_container(cid, force=True, v=True)
        except self.docker.errors.NotFound:
            pass

    def state(self, cid):
        try:
            return self.api.inspect_container(cid)["State"]["Status"]
        except self.docker.errors.NotFound:
            return "missing"

    def addresses(self, cid):
        nets = self.api.inspect_container(cid)["NetworkSettings"]["Networks"]
        return {k: v.get("IPAddress") for k, v in nets.items() if v.get("IPAddress")}

    def exec(self, cid, argv, timeout=60):
        # busybox `timeout` bounds the runtime inside the container; nothing ever runs on the host.
        try:
            ex = self.api.exec_create(cid, ["timeout", str(int(timeout)), *argv], stdout=True, stderr=True, privileged=False, user="")
            out = self.api.exec_start(ex["Id"], stream=False, demux=False)
            code = self.api.exec_inspect(ex["Id"]).get("ExitCode")
        except self.docker.errors.APIError as e:
            raise DriverError(f"exec in {cid[:12]}: {e.explanation}") from None
        return (code if code is not None else -1), (out or b"").decode("utf-8", errors="replace")[-200_000:]

    def commit(self, cid, repository, tag):
        try:
            return self.api.commit(cid, repository=repository, tag=tag, pause=True,
                                   changes=None, conf=None, message="cyber-range snapshot")["Id"]
        except self.docker.errors.APIError as e:
            raise DriverError(f"commit {cid[:12]}: {e.explanation}") from None

    def remove_image(self, image_id):
        try:
            self.api.remove_image(image_id, force=True)
        except self.docker.errors.NotFound:
            pass

    def stats(self, cid):
        s = self.api.stats(cid, stream=False)
        cpu = s["cpu_stats"]
        pre = s.get("precpu_stats") or {}
        cpu_delta = cpu["cpu_usage"]["total_usage"] - (pre.get("cpu_usage") or {}).get("total_usage", 0)
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        ncpu = cpu.get("online_cpus") or 1
        mem = s.get("memory_stats") or {}
        return {"cpu_pct": round(cpu_delta / sys_delta * ncpu * 100, 2) if sys_delta > 0 else 0.0,
                "mem_bytes": mem.get("usage", 0) - (mem.get("stats") or {}).get("inactive_file", 0),
                "mem_limit": mem.get("limit", 0), "pids": (s.get("pids_stats") or {}).get("current", 0)}

    def create_sensor(self, spec):
        host_config = self.api.create_host_config(
            network_mode="host", cap_drop=["ALL"], cap_add=spec.cap_add, security_opt=["no-new-privileges:true"],
            mem_limit=f"{spec.memory_mb}m", memswap_limit=f"{spec.memory_mb}m", nano_cpus=int(spec.cpus * 1e9), pids_limit=256,
            tmpfs={p: "rw,nosuid,nodev,size=128m" for p in spec.tmpfs}, privileged=False,
            log_config={"type": "json-file", "config": {"max-size": "1m", "max-file": "2"}}, restart_policy={"Name": "no"},
        )
        try:
            c = self.api.create_container(spec.image, command=spec.command, entrypoint=spec.entrypoint, name=spec.name, labels=spec.labels,
                                          host_config=host_config, detach=True)
            self.api.start(c["Id"])
        except self.docker.errors.APIError as e:
            raise DriverError(f"sensor {spec.name}: {e.explanation}") from None
        return c["Id"]

    def read_file(self, cid, path, offset, limit):
        # path and numbers come from constants/the DB, never from users
        try:
            ex = self.api.exec_create(cid, ["sh", "-c", f"tail -c +{int(offset) + 1} {path} 2>/dev/null | head -c {int(limit)}"], stdout=True, stderr=False)
            return self.api.exec_start(ex["Id"], stream=False, demux=False) or b""
        except self.docker.errors.APIError as e:
            raise DriverError(f"read {path} in {cid[:12]}: {e.explanation}") from None

    def list_managed(self, rid):
        flt = {"label": [f"{LABEL}=true", f"cyber-range.instance={rid}"]}
        return {"containers": [c["Id"] for c in self.api.containers(all=True, filters=flt)],
                "networks": [n["Id"] for n in self.api.networks(filters=flt)]}


class FakeDriver(LabDriver):
    """In-memory driver for tests and environments without Docker. Mirrors Docker's observable behaviour."""

    name = "fake"
    _lock = threading.Lock()
    containers: dict = {}
    networks: dict = {}
    images: dict = {}
    fail_on: set = set()

    def _id(self):
        return uuid.uuid4().hex

    def ensure_image(self, ref):
        if "image" in self.fail_on:
            raise DriverError(f"cannot pull image {ref}")

    def create_network(self, name, cidr, gateway, labels):
        import ipaddress
        with self._lock:
            for n in self.networks.values():
                if ipaddress.ip_network(n["cidr"]).overlaps(ipaddress.ip_network(cidr)):
                    raise DriverError(f"network {name} ({cidr}): Pool overlaps with other one on this address space")
            i = self._id()
            self.networks[i] = {"name": name, "cidr": cidr, "gateway": gateway, "labels": labels}
            return i

    def remove_network(self, net_id):
        self.networks.pop(net_id, None)

    def create_container(self, spec):
        if "container" in self.fail_on:
            raise DriverError(f"container {spec.name}: simulated failure")
        import ipaddress
        i = self._id()
        addrs = {}
        for a in spec.attachments:
            net = next(n for n in self.networks.values() if n["name"] == a["network"])
            if a["ip"]:
                addrs[a["network"]] = a["ip"]
            else:
                hosts = [str(h) for h in ipaddress.ip_network(net["cidr"]).hosts()]
                taken = {c["addrs"].get(a["network"]) for c in self.containers.values()} | {net["gateway"]}
                addrs[a["network"]] = next(h for h in hosts if h not in taken)
        self.containers[i] = {"spec": spec, "state": "created", "addrs": addrs, "labels": spec.labels}
        return i

    def start(self, cid):
        self.containers[cid]["state"] = "running"

    def stop(self, cid, timeout=5):
        if cid in self.containers:
            self.containers[cid]["state"] = "exited"

    def remove_container(self, cid):
        self.containers.pop(cid, None)

    def state(self, cid):
        return self.containers.get(cid, {}).get("state", "missing")

    def addresses(self, cid):
        return dict(self.containers[cid]["addrs"])

    exec_handler = None  # tests install a callable(container_record, argv) -> (code, output)

    def exec(self, cid, argv, timeout=60):
        if cid not in self.containers or self.containers[cid]["state"] != "running":
            raise DriverError("container is not running")
        if self.exec_handler:
            return self.exec_handler(self.containers[cid], argv)
        return 0, ""

    def commit(self, cid, repository, tag):
        i = "sha256:" + self._id()
        self.images[i] = {"from": cid, "ref": f"{repository}:{tag}"}
        return i

    def remove_image(self, image_id):
        self.images.pop(image_id, None)

    def stats(self, cid):
        return {"cpu_pct": 0.5, "mem_bytes": 4 * 1024 * 1024, "mem_limit": self.containers[cid]["spec"].memory_mb * 1024 * 1024, "pids": 2}

    def list_managed(self, rid):
        return {"containers": [k for k, v in self.containers.items() if v["labels"].get("cyber-range.instance") == rid],
                "networks": [k for k, v in self.networks.items() if v["labels"].get("cyber-range.instance") == rid]}

    files: dict = {}   # {(container_id, path): bytes} sensor log content for tests

    def create_sensor(self, spec):
        if "sensor" in self.fail_on:
            raise DriverError(f"sensor {spec.name}: simulated failure")
        i = self._id()
        self.containers[i] = {"spec": spec, "state": "running", "addrs": {}, "labels": spec.labels, "sensor": True}
        return i

    def read_file(self, cid, path, offset, limit):
        if cid not in self.containers:
            raise DriverError("container is gone")
        return self.files.get((cid, path), b"")[offset:offset + limit]

    @classmethod
    def reset_state(cls):
        cls.containers, cls.networks, cls.images, cls.fail_on, cls.files = {}, {}, {}, set(), {}


_driver: LabDriver | None = None


def get_driver() -> LabDriver:
    global _driver
    if _driver is None:
        kind = os.environ.get("CR_LAB_DRIVER", "docker")
        _driver = FakeDriver() if kind == "fake" else DockerDriver()
    return _driver


def set_driver(d: LabDriver | None) -> None:
    global _driver
    _driver = d
