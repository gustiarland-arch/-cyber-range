"""VM adapters for `vm` topology nodes: KVM through libvirt, or a remote Proxmox VE cluster.

Selection is explicit: CR_VM_PROVIDER=none|libvirt|proxmox (same value on the backend and the lab worker). Nothing is
assumed from the host; without a provider VM nodes keep running as hardened containers ("compatible mode").

Safety rules shared by both adapters:
* Only operator-allowlisted base images / templates can be used (CR_LIBVIRT_IMAGES, CR_PROXMOX_TEMPLATES).
* VMs are created with a `cr-<runtime>-<node>` name and tagged with the lab instance; the adapters refuse to touch a
  VM that does not carry that marker, so they can never stop or delete a VM the platform did not create.
* libvirt VMs boot from a per-lab copy-on-write overlay (the base image is never written) and attach only to the lab's
  own isolated Docker bridge. No host devices, no shared folders, graphics bound to 127.0.0.1 only.
* Proxmox VMs are linked clones placed in a dedicated pool, attached to an operator-provided isolated bridge
  (CR_PROXMOX_BRIDGE, no uplink) with a per-subnet VLAN tag from CR_PROXMOX_VLAN_RANGE, inside a VMID range.
"""
import os
import re
import subprocess  # noqa: S404 - only fixed qemu-img argument lists, never a shell
import time
import xml.sax.saxutils as sx
from dataclasses import dataclass, field

import httpx

NAME_RX = re.compile(r"^cr-[a-z0-9]{6,32}-[a-z0-9-]{1,40}$")
SNAP_RX = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
LIMITS = {"vcpus": (1, 8), "memory_mb": (256, 16384)}


class VmError(Exception):
    pass


@dataclass
class VmSpec:
    name: str
    template: str
    vcpus: int
    memory_mb: int
    instance: str                                       # runtime id, stored as the ownership marker
    nics: list[dict] = field(default_factory=list)      # [{"bridge": "br-…", "subnet_key": "dmz", "mac": "52:54:00:…", "vlan": 120}]


def provider_name() -> str:
    v = os.environ.get("CR_VM_PROVIDER", "none").strip().lower()
    return v if v in ("libvirt", "proxmox") else "none"


def _csv_map(env: str) -> dict[str, str]:
    out = {}
    for part in (os.environ.get(env) or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip() and v.strip():
                out[k.strip()] = v.strip()
    return out


def templates() -> dict[str, str]:
    """Allowlisted VM templates: name -> libvirt base image path or Proxmox template VMID."""
    if _provider is not None and getattr(_provider, "template_map", None) is not None:
        return dict(_provider.template_map)
    p = provider_name()
    if p == "libvirt":
        d = os.environ.get("CR_LIBVIRT_IMAGE_DIR", "/var/lib/cyber-range/vm-images")
        return {k: os.path.join(d, os.path.basename(v)) for k, v in _csv_map("CR_LIBVIRT_IMAGES").items()}
    if p == "proxmox":
        return {k: v for k, v in _csv_map("CR_PROXMOX_TEMPLATES").items() if v.isdigit()}
    return {}


def mac_for(name: str, idx: int) -> str:
    import hashlib
    h = hashlib.sha256(f"{name}/{idx}".encode()).digest()
    return "52:54:00:%02x:%02x:%02x" % (h[0], h[1], h[2])


class VmProvider:
    name = "none"

    def ping(self) -> dict:
        raise NotImplementedError

    def create(self, spec: VmSpec) -> str:
        raise NotImplementedError

    def start(self, ref: str) -> None:
        raise NotImplementedError

    def stop(self, ref: str) -> None:
        raise NotImplementedError

    def destroy(self, ref: str) -> None:
        raise NotImplementedError

    def state(self, ref: str) -> str:
        raise NotImplementedError

    def snapshot(self, ref: str, snap: str) -> None:
        raise NotImplementedError

    def revert(self, ref: str, snap: str) -> None:
        raise NotImplementedError

    def delete_snapshot(self, ref: str, snap: str) -> None:
        raise NotImplementedError

    def list_managed(self, instance: str) -> list[str]:
        raise NotImplementedError


# ------------------------------------------------------------------ libvirt / KVM
LIBVIRT_STATES = {0: "unknown", 1: "running", 2: "running", 3: "paused", 4: "stopping", 5: "stopped", 6: "crashed", 7: "suspended"}
META_NS = "https://cyber-range.local/vm/1"


class LibvirtProvider(VmProvider):
    name = "libvirt"

    def __init__(self, uri: str | None = None):
        self.uri = uri or os.environ.get("CR_LIBVIRT_URI", "qemu:///system")
        self.disk_dir = os.environ.get("CR_LIBVIRT_DISK_DIR", "/var/lib/cyber-range/vm-disks")
        self.domain_type = os.environ.get("CR_LIBVIRT_DOMAIN_TYPE", "kvm")   # "qemu" = software emulation (slow, for tests)
        self._conn = None

    def conn(self):
        try:
            import libvirt
        except ImportError:
            raise VmError("libvirt-python is not installed in this image (build with WITH_LIBVIRT=1)") from None
        if self._conn is None or not self._conn.isAlive():
            try:
                self._conn = libvirt.open(self.uri)
            except libvirt.libvirtError as e:
                raise VmError(f"cannot connect to libvirt at {self.uri}: {e}") from None
        return self._conn

    def ping(self) -> dict:
        c = self.conn()
        return {"ok": True, "uri": self.uri, "hypervisor": c.getType(), "version": c.getLibVersion(), "domain_type": self.domain_type}

    def _dom(self, ref: str):
        import libvirt
        if not NAME_RX.match(ref):
            raise VmError(f"refusing to manage VM {ref!r}: not a platform VM name")
        try:
            d = self.conn().lookupByName(ref)
        except libvirt.libvirtError:
            return None
        try:
            if d.metadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT, META_NS) is None:
                raise VmError(f"refusing to manage VM {ref}: no cyber-range ownership marker")
        except libvirt.libvirtError:
            raise VmError(f"refusing to manage VM {ref}: no cyber-range ownership marker") from None
        return d

    def _xml(self, spec: VmSpec, disk: str) -> str:
        e = sx.escape
        nics = "".join(
            f"<interface type='bridge'><source bridge='{e(n['bridge'])}'/><mac address='{e(n['mac'])}'/><model type='virtio'/></interface>"
            for n in spec.nics)
        return f"""<domain type='{e(self.domain_type)}'>
  <name>{e(spec.name)}</name>
  <metadata><cr:lab xmlns:cr='{META_NS}' instance='{e(spec.instance)}' template='{e(spec.template)}'/></metadata>
  <memory unit='MiB'>{spec.memory_mb}</memory>
  <vcpu>{spec.vcpus}</vcpu>
  <os><type arch='x86_64' machine='pc'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='{e(disk)}'/><target dev='vda' bus='virtio'/></disk>
    {nics}
    <serial type='pty'/><console type='pty'/>
    <graphics type='vnc' listen='127.0.0.1' autoport='yes'/>
    <memballoon model='virtio'/>
  </devices>
</domain>"""

    def create(self, spec: VmSpec) -> str:
        import libvirt
        if not NAME_RX.match(spec.name):
            raise VmError(f"invalid VM name {spec.name}")
        base = templates().get(spec.template)
        if not base:
            raise VmError(f"VM template {spec.template!r} is not allowlisted (CR_LIBVIRT_IMAGES)")
        if not os.path.isfile(base):
            raise VmError(f"base image for {spec.template!r} not found on the lab host")
        os.makedirs(self.disk_dir, mode=0o711, exist_ok=True)  # qemu runs as its own user and needs to traverse it
        disk = os.path.join(self.disk_dir, f"{spec.name}.qcow2")
        if os.path.exists(disk):
            os.unlink(disk)
        r = subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, disk],  # noqa: S603,S607
                           capture_output=True, text=True, timeout=120, check=False)
        if r.returncode != 0:
            raise VmError(f"qemu-img failed: {r.stderr.strip()[:300]}")
        try:
            self.conn().defineXML(self._xml(spec, disk))
        except libvirt.libvirtError as e:
            os.unlink(disk)
            raise VmError(f"libvirt define failed: {e}") from None
        return spec.name

    def start(self, ref: str) -> None:
        import libvirt
        d = self._dom(ref)
        if d is None:
            raise VmError(f"VM {ref} no longer exists; reset the lab")
        if not d.isActive():
            try:
                d.create()
            except libvirt.libvirtError as e:
                raise VmError(f"VM {ref} failed to start: {e}") from None

    def stop(self, ref: str) -> None:
        d = self._dom(ref)
        if d is not None and d.isActive():
            d.destroy()   # hard power-off: lab VMs are disposable and must stop within the kill-switch window

    def destroy(self, ref: str) -> None:
        import libvirt
        d = self._dom(ref)
        if d is not None:
            if d.isActive():
                d.destroy()
            flags = getattr(libvirt, "VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA", 1) | getattr(libvirt, "VIR_DOMAIN_UNDEFINE_NVRAM", 4)
            d.undefineFlags(flags)
        disk = os.path.join(self.disk_dir, f"{ref}.qcow2")
        if NAME_RX.match(ref) and os.path.isfile(disk):
            os.unlink(disk)

    def state(self, ref: str) -> str:
        d = self._dom(ref)
        if d is None:
            return "missing"
        return LIBVIRT_STATES.get(d.state()[0], "unknown")

    def snapshot(self, ref: str, snap: str) -> None:
        import libvirt
        if not SNAP_RX.match(snap):
            raise VmError("invalid snapshot name")
        d = self._dom(ref)
        try:
            d.snapshotCreateXML(f"<domainsnapshot><name>{snap}</name></domainsnapshot>", 0)
        except libvirt.libvirtError as e:
            raise VmError(f"snapshot of {ref} failed: {e}") from None

    def revert(self, ref: str, snap: str) -> None:
        import libvirt
        d = self._dom(ref)
        try:
            d.revertToSnapshot(d.snapshotLookupByName(snap, 0), 0)
        except libvirt.libvirtError as e:
            raise VmError(f"revert of {ref} failed: {e}") from None

    def delete_snapshot(self, ref: str, snap: str) -> None:
        import libvirt
        d = self._dom(ref)
        if d is None:
            return
        try:
            d.snapshotLookupByName(snap, 0).delete(0)
        except libvirt.libvirtError:
            pass

    def list_managed(self, instance: str) -> list[str]:
        prefix = f"cr-{instance}-"
        return [n for n in (d.name() for d in self.conn().listAllDomains(0)) if n.startswith(prefix)]


# ------------------------------------------------------------------ Proxmox VE (REST API, API token auth)
class ProxmoxProvider(VmProvider):
    name = "proxmox"

    def __init__(self):
        self.url = os.environ.get("CR_PROXMOX_URL", "").rstrip("/")
        self.node = os.environ.get("CR_PROXMOX_NODE", "")
        self.pool = os.environ.get("CR_PROXMOX_POOL", "cyber-range")
        self.bridge = os.environ.get("CR_PROXMOX_BRIDGE", "")
        self.storage = os.environ.get("CR_PROXMOX_STORAGE", "")
        lo, _, hi = os.environ.get("CR_PROXMOX_VMID_RANGE", "9000-9999").partition("-")
        self.vmid_range = (int(lo), int(hi or lo))
        vlo, _, vhi = os.environ.get("CR_PROXMOX_VLAN_RANGE", "").partition("-")
        self.vlan_range = (int(vlo), int(vhi or vlo)) if vlo.isdigit() else None
        self.verify = os.environ.get("CR_PROXMOX_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
        tid, secret = os.environ.get("CR_PROXMOX_TOKEN_ID", ""), os.environ.get("CR_PROXMOX_TOKEN_SECRET", "")
        self._auth = f"PVEAPIToken={tid}={secret}" if tid and secret else ""
        self.timeout = float(os.environ.get("CR_PROXMOX_TASK_TIMEOUT", "300"))

    def _check(self):
        missing = [k for k, v in (("CR_PROXMOX_URL", self.url), ("CR_PROXMOX_NODE", self.node), ("CR_PROXMOX_BRIDGE", self.bridge),
                                  ("CR_PROXMOX_TOKEN_ID/SECRET", self._auth)) if not v]
        if missing:
            raise VmError("Proxmox is not fully configured: " + ", ".join(missing))

    def _req(self, method: str, path: str, **kw):
        self._check()
        try:
            r = httpx.request(method, f"{self.url}/api2/json{path}", headers={"Authorization": self._auth}, verify=self.verify, timeout=30, **kw)
        except httpx.HTTPError as e:
            raise VmError(f"Proxmox API unreachable: {type(e).__name__}") from None
        if r.status_code >= 400:
            raise VmError(f"Proxmox API {method} {path}: HTTP {r.status_code} {r.text[:200]}")
        return (r.json() or {}).get("data")

    def _wait(self, upid):
        if not isinstance(upid, str) or not upid.startswith("UPID:"):
            return
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            st = self._req("GET", f"/nodes/{self.node}/tasks/{upid}/status") or {}
            if st.get("status") == "stopped":
                if st.get("exitstatus") not in ("OK", None):
                    raise VmError(f"Proxmox task failed: {st.get('exitstatus')}")
                return
            time.sleep(float(os.environ.get("CR_PROXMOX_POLL_SECONDS", "2")))
        raise VmError("Proxmox task timed out")

    def ping(self) -> dict:
        v = self._req("GET", "/version") or {}
        return {"ok": True, "url": self.url, "node": self.node, "version": v.get("version"), "pool": self.pool, "bridge": self.bridge}

    def _vms(self) -> list[dict]:
        return self._req("GET", f"/nodes/{self.node}/qemu") or []

    def _find(self, ref: str) -> int | None:
        """ref is the VM name; returns its VMID only if it is ours (name, VMID range and tag all match)."""
        if not NAME_RX.match(ref):
            raise VmError(f"refusing to manage VM {ref!r}: not a platform VM name")
        for v in self._vms():
            if v.get("name") == ref:
                vmid = int(v["vmid"])
                tags = set(str(v.get("tags") or "").replace(",", ";").split(";"))
                if not (self.vmid_range[0] <= vmid <= self.vmid_range[1]) or "cyberrange" not in tags:
                    raise VmError(f"refusing to manage VM {ref} (vmid {vmid}): outside the platform range or untagged")
                return vmid
        return None

    def _vlan(self, subnet_key: str, instance: str) -> int | None:
        if not self.vlan_range:
            return None
        import hashlib
        lo, hi = self.vlan_range
        return lo + int(hashlib.sha256(f"{instance}/{subnet_key}".encode()).hexdigest(), 16) % (hi - lo + 1)

    def create(self, spec: VmSpec) -> str:
        tmpl = templates().get(spec.template)
        if not tmpl:
            raise VmError(f"VM template {spec.template!r} is not allowlisted (CR_PROXMOX_TEMPLATES)")
        if self._find(spec.name) is not None:
            self.destroy(spec.name)
        used = {int(v["vmid"]) for v in self._vms()}
        vmid = next((i for i in range(self.vmid_range[0], self.vmid_range[1] + 1) if i not in used), None)
        if vmid is None:
            raise VmError("no free VMID left in CR_PROXMOX_VMID_RANGE")
        body = {"newid": vmid, "name": spec.name, "full": 0, "pool": self.pool}
        if self.storage:
            body["storage"] = self.storage
        self._wait(self._req("POST", f"/nodes/{self.node}/qemu/{tmpl}/clone", data=body))
        cfg = {"cores": spec.vcpus, "memory": spec.memory_mb, "tags": f"cyberrange;cr-{spec.instance}",
               "description": f"cyber-range lab instance {spec.instance}; managed by the platform, do not edit"}
        for i, n in enumerate(spec.nics[:8]):
            tag = self._vlan(n["subnet_key"], spec.instance)
            cfg[f"net{i}"] = f"virtio={n['mac']},bridge={self.bridge},firewall=1" + (f",tag={tag}" if tag else "")
        self._wait(self._req("POST", f"/nodes/{self.node}/qemu/{vmid}/config", data=cfg))
        return spec.name

    def _vmid(self, ref):
        vmid = self._find(ref)
        if vmid is None:
            raise VmError(f"VM {ref} no longer exists; reset the lab")
        return vmid

    def start(self, ref: str) -> None:
        self._wait(self._req("POST", f"/nodes/{self.node}/qemu/{self._vmid(ref)}/status/start"))

    def stop(self, ref: str) -> None:
        vmid = self._find(ref)
        if vmid is not None and self.state(ref) == "running":
            self._wait(self._req("POST", f"/nodes/{self.node}/qemu/{vmid}/status/stop"))

    def destroy(self, ref: str) -> None:
        vmid = self._find(ref)
        if vmid is None:
            return
        if self.state(ref) == "running":
            self._wait(self._req("POST", f"/nodes/{self.node}/qemu/{vmid}/status/stop"))
        self._wait(self._req("DELETE", f"/nodes/{self.node}/qemu/{vmid}", params={"purge": 1, "destroy-unreferenced-disks": 1}))

    def state(self, ref: str) -> str:
        vmid = self._find(ref)
        if vmid is None:
            return "missing"
        st = (self._req("GET", f"/nodes/{self.node}/qemu/{vmid}/status/current") or {}).get("status")
        return {"running": "running", "stopped": "stopped", "paused": "paused"}.get(st, "unknown")

    def snapshot(self, ref: str, snap: str) -> None:
        if not SNAP_RX.match(snap):
            raise VmError("invalid snapshot name")
        self._wait(self._req("POST", f"/nodes/{self.node}/qemu/{self._vmid(ref)}/snapshot", data={"snapname": snap}))

    def revert(self, ref: str, snap: str) -> None:
        self._wait(self._req("POST", f"/nodes/{self.node}/qemu/{self._vmid(ref)}/snapshot/{snap}/rollback"))

    def delete_snapshot(self, ref: str, snap: str) -> None:
        vmid = self._find(ref)
        if vmid is not None:
            self._wait(self._req("DELETE", f"/nodes/{self.node}/qemu/{vmid}/snapshot/{snap}"))

    def list_managed(self, instance: str) -> list[str]:
        prefix = f"cr-{instance}-"
        return [v["name"] for v in self._vms() if str(v.get("name", "")).startswith(prefix)]


# ------------------------------------------------------------------ in-memory provider for tests
class FakeVmProvider(VmProvider):
    name = "fake"
    vms: dict = {}
    fail_on: set = set()
    template_map = {"ubuntu-22.04": "fake", "win10-eval": "fake"}

    def ping(self):
        return {"ok": True}

    def create(self, spec):
        if "create" in self.fail_on:
            raise VmError("fake create failure")
        if spec.template not in self.template_map:
            raise VmError(f"VM template {spec.template!r} is not allowlisted")
        self.vms[spec.name] = {"spec": spec, "state": "stopped", "snaps": set()}
        return spec.name

    def start(self, ref):
        if "start" in self.fail_on:
            raise VmError("fake start failure")
        self.vms[ref]["state"] = "running"

    def stop(self, ref):
        if ref in self.vms:
            self.vms[ref]["state"] = "stopped"

    def destroy(self, ref):
        self.vms.pop(ref, None)

    def state(self, ref):
        return self.vms[ref]["state"] if ref in self.vms else "missing"

    def snapshot(self, ref, snap):
        self.vms[ref]["snaps"].add(snap)

    def revert(self, ref, snap):
        if snap not in self.vms[ref]["snaps"]:
            raise VmError("no such snapshot")

    def delete_snapshot(self, ref, snap):
        if ref in self.vms:
            self.vms[ref]["snaps"].discard(snap)

    def list_managed(self, instance):
        return [n for n in self.vms if n.startswith(f"cr-{instance}-")]


_provider: VmProvider | None = None


def get_vm_provider() -> VmProvider | None:
    global _provider
    if _provider is not None:
        return _provider
    p = provider_name()
    if p == "libvirt":
        _provider = LibvirtProvider()
    elif p == "proxmox":
        _provider = ProxmoxProvider()
    return _provider


def set_vm_provider(p: VmProvider | None) -> None:
    global _provider
    _provider = p


def vm_capability(probe: bool = False) -> dict:
    p = provider_name()
    kvm = os.path.exists("/dev/kvm")
    proxmox = bool(os.environ.get("CR_PROXMOX_URL"))
    out = {"provider": p, "kvm_device": kvm, "proxmox_configured": proxmox, "supported": p != "none" or _provider is not None,
           "templates": sorted(templates()), "limits": LIMITS}
    if _provider is not None and p == "none":
        out["provider"] = _provider.name
    if out["supported"]:
        out["note"] = f"VM nodes are created as real VMs via {out['provider']}. Templates: {', '.join(out['templates']) or 'none allowlisted yet'}."
    else:
        out["note"] = ("No VM provider is configured (CR_VM_PROVIDER=libvirt or proxmox). VM nodes run as hardened containers (compatible mode). "
                       + ("/dev/kvm is present on this host, so libvirt can be enabled." if kvm else ""))
    if probe and out["supported"]:
        try:
            out["probe"] = get_vm_provider().ping()
        except (VmError, NotImplementedError) as e:
            out["probe"] = {"ok": False, "error": str(e)[:300]}
    return out
