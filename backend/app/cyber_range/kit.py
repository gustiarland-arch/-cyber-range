"""Lab Kit (v1.6): download a lab as a ZIP and run it on your own computer instead of on the CYBER RANGE server.

Two formats, both built from the same deployment plan the server uses (same image allowlist, same validation):
* ``docker``  - ``docker-compose.yml``. Every node is a hardened container (VM nodes run in compatible mode, exactly as
  on a server without a VM provider). Subnets are *internal* bridges: no egress, no masquerade, no host address.
* ``vagrant`` - ``Vagrantfile`` + provisioning scripts. Every host node becomes a real VM (VirtualBox or libvirt).
  Subnets become VirtualBox internal networks / isolated libvirt networks. A boot-time ``isolate.sh`` blocks new
  outbound connections on the Vagrant NAT interface, so after provisioning the lab has no internet egress either.

Safety
* A kit contains no secrets, no server address, no tokens and no flags: labs never hold challenge flags (flags are
  graded on the server), and the topology document only describes hosts, subnets and allowlisted images.
* Only images enabled in the server allowlist and Vagrant boxes in ``CR_KIT_VAGRANT_BOXES`` are written into a kit.
* Nothing here runs anything; the kit is generated text. Downloads are permission-checked, rate limited and audited.
"""
import hashlib
import io
import ipaddress
import json
import re
import zipfile

import pathlib

import yaml

from app.cyber_range.engine.planner import PlanError, build_plan

FORMATS = ("docker", "vagrant")
BOX_RX = re.compile(r"^[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,64}$")
NAME_RX = re.compile(r"[^a-z0-9-]")
MAX_VMS = 20
VM_DEFAULT_MB = 512
MAX_PACKAGES_PER_VM = 4

# Server software a Vagrant kit can install on a VM during first provisioning (while the NAT adapter still has internet).
# Fixed allowlist: the operator picks sets by key, never arbitrary commands. Ubuntu defaults, no extra accounts or passwords.
SERVER_PACKAGES: dict[str, dict] = {
    "web-apache": {"title": "Web server Apache + PHP", "apt": ["apache2", "php", "libapache2-mod-php"], "services": ["apache2"], "ports": "80/tcp"},
    "web-nginx": {"title": "Web server Nginx", "apt": ["nginx"], "services": ["nginx"], "ports": "80/tcp"},
    "db-mysql": {"title": "Database MySQL", "apt": ["mysql-server"], "services": ["mysql"], "ports": "3306/tcp (bawaan hanya localhost)"},
    "ftp": {"title": "FTP server vsftpd", "apt": ["vsftpd"], "services": ["vsftpd"], "ports": "21/tcp"},
    "mail": {"title": "Mail server Postfix + Dovecot IMAP", "apt": ["postfix", "dovecot-imapd"], "services": ["postfix", "dovecot"], "ports": "25/tcp, 143/tcp"},
    "dns": {"title": "DNS server BIND9", "apt": ["bind9", "bind9-utils"], "services": ["named"], "ports": "53/udp, 53/tcp"},
    "smb": {"title": "File server Samba", "apt": ["samba"], "services": ["smbd"], "ports": "139/tcp, 445/tcp"},
    "ssh": {"title": "SSH server", "apt": ["openssh-server"], "services": ["ssh"], "ports": "22/tcp"},
}


OFFICE_DEFAULT_PACKAGES = {"lab-dc": ["dns", "smb"], "lab-portal": ["web-apache"], "lab-ws": []}
OFFICE_ROLES = {"lab-dc": "dc", "lab-portal": "portal", "lab-ws": "ws"}
OFFICE_DOMAIN = "lab.local"
DEFAULT_WINDOWS_DC_BOX = "gusztavvargadr/windows-server-2022-standard"
WINDOWS_DC_CPUS, WINDOWS_DC_MB = 2, 2048
DEFAULT_WINDOWS_PC_BOX = "gusztavvargadr/windows-11"
WINDOWS_PC_CPUS, WINDOWS_PC_MB = 2, 4096
ASSETS = pathlib.Path(__file__).resolve().parent
OFFICE_FILES = ("common.py", "agent.py", "bot.py", "portal.py")      # from office_lab/, the same scripts as the lab images
WINDOWS_DC_FILES = ("dc-1-forest.ps1", "dc-2-org.ps1")
WINDOWS_PC_FILES = ("pc-1-join.ps1", "pc-2-employee.ps1", "employee.ps1")
WINDOWS_COMMON_FILES = ("telemetry.ps1", "export-events.ps1", "isolate.ps1")
JOIN_ADMIN = "andi.saputra"   # the DEMO IT admin (Domain Admins) joins the Windows PCs to the domain, as IT would


def office_role(image: str | None) -> str | None:
    """dc / portal / ws for the office lab images (cyber-range/lab-dc:1.0 ...), else None."""
    if not (image or "").startswith("cyber-range/lab-"):
        return None
    return OFFICE_ROLES.get(image.split(":")[0].rsplit("/", 1)[-1])


def parse_packages(items: list[str] | None) -> dict[str, list[str]]:
    """`node=set1,set2` entries -> {node: [sets]}. Only allowlisted set keys are accepted."""
    out: dict[str, list[str]] = {}
    problems = []
    if len(items or []) > MAX_VMS:
        raise KitError([f"Too many package entries (max {MAX_VMS})"])
    for item in items or []:
        if len(item or "") > 200:
            problems.append("Package entry too long")
            continue
        node, sep, sets = (item or "").partition("=")
        node = node.strip()
        if not sep or not node:
            problems.append(f"Bad package entry '{item[:60]}' (use node=set1,set2)")
            continue
        keys = [k.strip() for k in sets.split(",") if k.strip()]
        bad = [k for k in keys if k not in SERVER_PACKAGES]
        if bad:
            problems.append(f"Unknown server package '{bad[0][:40]}'")
            continue
        merged = sorted(set(out.get(node, [])) | set(keys))
        if len(merged) > MAX_PACKAGES_PER_VM:
            problems.append(f"At most {MAX_PACKAGES_PER_VM} server packages per VM ({node})")
            continue
        if merged:
            out[node] = merged
    if problems:
        raise KitError(problems)
    return out
ZIP_DATE = (2026, 1, 1, 0, 0, 0)  # fixed timestamps: the same lab always produces the same ZIP


class KitError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def parse_boxes(raw: str) -> dict[str, str]:
    out = {}
    for part in (raw or "").split(","):
        if "=" not in part:
            continue
        k, v = (x.strip() for x in part.split("=", 1))
        if k and BOX_RX.match(v):
            out[k] = v
    out.setdefault("default", "bento/ubuntu-24.04")
    return out


def _slug(s: str, n: int = 30) -> str:
    return re.sub("-+", "-", NAME_RX.sub("-", (s or "").lower())).strip("-")[:n].strip("-") or "x"


def _role(image: str | None) -> str:
    """Provisioning profile for a VM that replaces a container image (only the allowlisted defaults have a profile)."""
    ref = (image or "").split(":")[0].rsplit("/", 1)[-1]
    return {"nginx": "web", "redis": "redis"}.get(ref, "base")


def _alloc(networks: list[dict], nodes: list[dict]) -> None:
    """Give every interface without an address the lowest free host address of its subnet (Vagrant needs static IPs)."""
    used: dict[str, set[str]] = {n["subnet_key"]: {x for x in (n.get("gateway"), n["bridge_ip"]) if x} for n in networks}
    for node in nodes:
        for nic in node["nics"]:
            if nic["ip"]:
                used[nic["subnet_key"]].add(nic["ip"])
    cidr = {n["subnet_key"]: ipaddress.ip_network(n["cidr"]) for n in networks}
    for node in nodes:
        for nic in node["nics"]:
            if not nic["ip"]:
                free = next((str(h) for h in cidr[nic["subnet_key"]].hosts() if str(h) not in used[nic["subnet_key"]]), None)
                if free is None:
                    raise KitError([f"Subnet {nic['subnet_key']}: no free address for {node['label']}"])
                nic["ip"] = free
                used[nic["subnet_key"]].add(free)


def plan_for(doc: dict, images: list[dict], fmt: str, boxes: dict[str, str], packages: dict[str, list[str]] | None = None,
             windows_dc: bool = False, windows_box: str = DEFAULT_WINDOWS_DC_BOX, windows_pcs: list[str] | None = None,
             windows_pc_box: str = DEFAULT_WINDOWS_PC_BOX) -> dict:
    """Validate the topology with the server planner, then shape it for the chosen kit format.

    windows_dc (vagrant, office lab only): the domain controller becomes a Windows Server (Evaluation) VM with real Active
    Directory, and the portal/workstation VMs run the office lab scripts (simulated employees, host agent) against it.
    windows_pcs (needs windows_dc): these employee PCs become Windows 11 (Evaluation) VMs joined to the domain, each with
    its simulated employee working under a real domain account."""
    if fmt not in FORMATS:
        raise KitError([f"Unknown kit format '{fmt}' (use docker or vagrant)"])
    try:
        plan = build_plan(doc, images, vm_supported=False)
    except PlanError as e:
        raise KitError(e.problems) from None
    nodes_by_key = {n["key"]: n for n in doc.get("nodes", [])}
    nets = plan["networks"]
    packages = packages or {}
    windows_pcs = list(dict.fromkeys(windows_pcs or []))
    if windows_pcs and not windows_dc:
        raise KitError(["Windows 11 PCs need the Windows domain controller option (they join its domain)"])
    if fmt == "docker":
        if windows_dc:
            raise KitError(["A Windows domain controller needs the vagrant format (real VMs)"])
        if packages:
            raise KitError(["Server packages can only be installed in the vagrant format (real VMs)"])
        office = [c["label"] for c in plan["containers"] if c["image"].startswith("cyber-range/lab-")]
        if office:
            raise KitError([f"{', '.join(office[:5])}: office lab images (domain controller, portal, workstation) are built inside this app "
                            "and cannot be carried in a Docker kit; use the vagrant format (with server packages) instead"])
        return {"format": fmt, "networks": nets, "containers": plan["containers"], "vms": [], "skipped": plan["skipped"], "office": None,
                "totals": {"nodes": len(plan["containers"]), "cpus": plan["totals"]["cpus"], "memory_mb": plan["totals"]["memory_mb"],
                           "networks": len(nets)}}
    vms, problems = [], []
    for c in plan["containers"]:
        node = nodes_by_key.get(c["node_key"], {})
        props = node.get("properties") or {}
        is_vm = node.get("type") == "vm"
        tmpl = props.get("vm_template") if is_vm else None
        box = boxes.get(tmpl or "", boxes["default"]) if tmpl else boxes["default"]
        cpus = int(props.get("cpus") or 1) if is_vm else 1
        mem = int(props.get("memory_mb") or VM_DEFAULT_MB) if is_vm else VM_DEFAULT_MB
        cpus, mem = max(1, min(cpus, 8)), max(VM_DEFAULT_MB, min(mem, 16384))
        vms.append({"node_key": c["node_key"], "name": _slug(c["node_key"]), "label": c["label"], "hostname": c["hostname"][:63],
                    "box": box, "cpus": cpus, "memory_mb": mem, "role": _role(None if is_vm else c["image"]),
                    "router": bool(c["ip_forward"]), "image": None if is_vm else c["image"], "template": tmpl,
                    "nics": [{"subnet_key": a["subnet_key"], "ip": a["ip"]} for a in c["attachments"]], "packages": []})
    by_name = {v["name"]: v for v in vms}
    for v in vms:
        v["os"], v["office"] = "linux", ""
    if windows_dc:
        dcs = [v for v in vms if office_role(v.get("image")) == "dc"]
        if len(dcs) != 1:
            raise KitError(["The Windows domain controller option needs exactly one office domain controller node "
                            "(template 'Kantor dengan Active Directory')"])
        if not BOX_RX.match(windows_box or ""):
            raise KitError(["Invalid Windows box id (CR_KIT_WINDOWS_DC_BOX)"])
        dc = dcs[0]
        if len(dc["hostname"].split(".")[0]) > 15:
            problems.append(f"{dc['name']}: a Windows computer name has at most 15 characters")
        if packages.get(dc["name"]):
            problems.append(f"{dc['name']}: the Windows domain controller does not take Ubuntu server packages")
        dc.update(box=windows_box, os="windows", office="dc", role="windows-dc", cpus=WINDOWS_DC_CPUS, memory_mb=WINDOWS_DC_MB)
        for v in vms:
            r = office_role(v.get("image"))
            if r in ("portal", "ws"):
                v["office"], v["role"] = r, "base"
        if not BOX_RX.match(windows_pc_box or ""):
            raise KitError(["Invalid Windows PC box id (CR_KIT_WINDOWS_PC_BOX)"])
        for name in windows_pcs:
            v = by_name.get(name)
            if v is None or v["office"] != "ws":
                problems.append(f"{name[:40]}: only employee PCs of the office lab can run Windows 11")
                continue
            if len(v["hostname"].split(".")[0]) > 15:
                problems.append(f"{name}: a Windows computer name has at most 15 characters")
            if packages.get(name):
                problems.append(f"{name}: a Windows PC does not take Ubuntu server packages")
            v.update(box=windows_pc_box, os="windows", role="windows-pc", cpus=WINDOWS_PC_CPUS, memory_mb=WINDOWS_PC_MB)
    else:
        for v in vms:   # office lab nodes become plain Ubuntu VMs; start them with the closest server software
            if office_role(v.get("image")) and v["name"] not in packages:
                v["packages"] = OFFICE_DEFAULT_PACKAGES.get(v["image"].split(":")[0].rsplit("/", 1)[-1], [])
    for node, sets in packages.items():
        if node not in by_name:
            problems.append(f"Server packages for unknown VM '{node[:40]}'")
        else:
            by_name[node]["packages"] = sets
    if len(vms) > MAX_VMS:
        problems.append(f"{len(vms)} VMs is too many for one computer (max {MAX_VMS}); use the docker format for this lab")
    names = [v["name"] for v in vms]
    if len(set(names)) != len(names):
        problems.append("Two nodes map to the same VM name; give the nodes distinct keys")
    if problems:
        raise KitError(problems)
    _alloc(nets, vms)
    office = None
    if windows_dc:
        ip = {v["office"]: v["nics"][0]["ip"] for v in vms if v["office"] in ("dc", "portal") and v["nics"]}
        if "dc" not in ip:
            raise KitError(["The office domain controller needs a network connection"])
        dc = next(v for v in vms if v["office"] == "dc")
        for v in vms:
            if v["os"] == "windows" and v["office"] == "ws" and not v["nics"]:
                raise KitError([f"{v['name']}: a Windows PC needs a network connection to join the domain"])
        office = {"domain": OFFICE_DOMAIN, "dc_host": dc["hostname"].split(".")[0].lower(), "dc_ip": ip["dc"],
                  "peers": ",".join(f"{k}={ip[k]}" for k in ("dc", "portal") if k in ip)}
    return {"format": fmt, "networks": nets, "containers": [], "vms": vms, "skipped": plan["skipped"], "office": office,
            "totals": {"nodes": len(vms), "cpus": sum(v["cpus"] for v in vms), "memory_mb": sum(v["memory_mb"] for v in vms),
                       "networks": len(nets)}}


# ------------------------------------------------------------------ docker compose
def compose_doc(kp: dict, kit_id: str) -> dict:
    nkey = {n["subnet_key"]: f"net-{_slug(n['subnet_key'], 24)}" for n in kp["networks"]}
    networks = {}
    for n in kp["networks"]:
        networks[nkey[n["subnet_key"]]] = {
            "name": f"crk-{kit_id}-{_slug(n['subnet_key'], 24)}",
            "driver": "bridge", "internal": True,
            "driver_opts": {"com.docker.network.bridge.enable_ip_masquerade": "false",
                            "com.docker.network.bridge.enable_icc": "true",
                            "com.docker.network.bridge.inhibit_ipv4": "true"},
            "ipam": {"config": [{"subnet": n["cidr"], "gateway": n["bridge_ip"]}]},
            "labels": {"cyber-range.kit": kit_id, "cyber-range.subnet": n["name"]},
        }
    services = {}
    for c in kp["containers"]:
        sysctls = {"net.ipv4.ping_group_range": "0 2147483647"}
        if c["ip_forward"]:
            sysctls["net.ipv4.ip_forward"] = "1"
        svc = {
            "image": c["image"], "hostname": c["hostname"],
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "privileged": False, "init": True,
            "mem_limit": f"{c['memory_mb']}m", "memswap_limit": f"{c['memory_mb']}m", "cpus": c["cpus"], "pids_limit": 256,
            "sysctls": sysctls, "restart": "no",
            "logging": {"driver": "json-file", "options": {"max-size": "1m", "max-file": "2"}},
            "labels": {"cyber-range.kit": kit_id, "cyber-range.node": c["label"]},
        }
        if c.get("cap_add"):
            svc["cap_add"] = list(c["cap_add"])
        if c.get("command"):
            svc["command"] = list(c["command"])
        if c.get("tmpfs"):
            svc["tmpfs"] = [f"{p}:rw,nosuid,nodev,size=32m" for p in c["tmpfs"]]
        if c["attachments"]:
            svc["networks"] = {nkey[a["subnet_key"]]: ({"ipv4_address": a["ip"]} if a["ip"] else {}) for a in c["attachments"]}
        else:
            svc["network_mode"] = "none"
        services[_slug(c["node_key"])] = svc
    return {"name": f"cyber-range-kit-{kit_id}", "services": services, "networks": networks}


# ------------------------------------------------------------------ vagrant
def _rb(s: str) -> str:
    """Ruby single-quoted literal (only ' and \\ need escaping)."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def vagrantfile(kp: dict, kit_id: str, title: str) -> str:
    nets = {n["subnet_key"]: n for n in kp["networks"]}
    lines = []
    for v in kp["vms"]:
        nics, routes = [], []
        gw = None
        for nic in v["nics"]:
            n = nets[nic["subnet_key"]]
            net = ipaddress.ip_network(n["cidr"])
            nics.append("{ net: %s, ip: %s, mask: %s, host_ip: %s }" % (
                _rb(_slug(nic["subnet_key"], 24)), _rb(nic["ip"]), _rb(str(net.netmask)), _rb(n["bridge_ip"])))
            if gw is None and n.get("gateway") and n["gateway"] != nic["ip"]:
                gw = n["gateway"]
        own = {x["subnet_key"] for x in v["nics"]}
        if gw and not v["router"]:
            routes = [f"{n['cidr']}={gw}" for k, n in nets.items() if k not in own]
        lines.append("  { name: %s, hostname: %s, label: %s, box: %s, cpus: %d, memory: %d, role: %s, router: %s,\n"
                     "    nics: [%s],\n    routes: %s, packages: %s, os: %s, office: %s, ip: %s }," % (
                         _rb(v["name"]), _rb(v["hostname"]), _rb(v["label"]), _rb(v["box"]), v["cpus"], v["memory_mb"], _rb(v["role"]),
                         "true" if v["router"] else "false", ", ".join(nics), _rb(" ".join(routes)), _rb(" ".join(v.get("packages") or [])),
                         _rb(v.get("os", "linux")), _rb(v.get("office", "")), _rb(v["nics"][0]["ip"] if v["nics"] else "")))
    # The domain controller comes first: `vagrant up` creates VMs in this order and the PCs join its domain.
    lines.sort(key=lambda line: 0 if "office: 'dc'" in line or 'office: "dc"' in line else 1)
    nodes = "\n".join(lines)
    office = kp.get("office")
    office_head = office_linux = office_windows = ""
    if office:
        office_head = f"""
# Office lab: the seed for the DEMO employee passwords is created on THIS computer at the first `vagrant up` (.lab-seed)
# and handed to the VMs. It is not part of the downloaded kit and differs for every copy of the kit.
require "securerandom"
SEED_FILE = File.join(__dir__, ".lab-seed")
File.write(SEED_FILE, SecureRandom.hex(32)) unless File.exist?(SEED_FILE)
LAB_SEED = File.read(SEED_FILE).strip
Dir.mkdir(File.join(__dir__, "telemetry")) unless Dir.exist?(File.join(__dir__, "telemetry"))
OFFICE_DOMAIN = {_rb(office["domain"])}
OFFICE_PEERS = {_rb(office["peers"])}
OFFICE_DC_HOST = {_rb(office["dc_host"])}
OFFICE_FILES = %w[{" ".join(f[:-3] for f in OFFICE_FILES)}]
"""
        office_linux = """      unless n[:office].empty?
        # telemetry/<node>.jsonl in the kit folder (VirtualBox shared folder); kirim-ke-siem ships it to the SIEM
        m.vm.synced_folder "telemetry", "/cr-telemetry", mount_options: ["dmode=777", "fmode=666"]
        m.vm.provider "libvirt" do |lv, o|
          o.vm.synced_folder "telemetry", "/cr-telemetry", disabled: true
        end
        OFFICE_FILES.each do |f|
          m.vm.provision "office-#{f}", type: "file", source: "provision/office/#{f}.py", destination: "/tmp/cr-office/#{f}.py"
        end
        m.vm.provision "office", type: "shell", path: "provision/office.sh", args: [n[:office]],
          env: { "CR_LAB_SEED" => LAB_SEED, "CR_DOMAIN" => OFFICE_DOMAIN, "CR_PEERS" => OFFICE_PEERS, "CR_NODE" => n[:name],
                 "CR_IP" => n[:ip], "CR_DC_HOST" => OFFICE_DC_HOST, "CR_EVENTS" => "/cr-telemetry/#{n[:name]}.jsonl" }
      end
"""
        office_windows = """      if n[:os] == "windows"
        # Windows (Evaluation): the domain controller with real Active Directory, or a Windows 11 PC joined to it.
        # VirtualBox only.
        m.vm.guest = :windows
        m.vm.communicator = "winrm"
        m.vm.boot_timeout = 1800
        m.winrm.retry_limit = 30
        m.winrm.retry_delay = 10
        m.vm.synced_folder "telemetry", "C:/cr-telemetry"
        if n[:office] == "dc"
          m.vm.provision "forest", type: "shell", path: "provision/windows/dc-1-forest.ps1", reboot: true
          m.vm.provision "org", type: "shell", path: "provision/windows/dc-2-org.ps1", args: ["-Seed", LAB_SEED]
        else
          m.vm.provision "join", type: "shell", path: "provision/windows/pc-1-join.ps1", args: ["-Seed", LAB_SEED, "-LabIp", n[:ip]],
            reboot: true
          m.vm.provision "employee-script", type: "file", source: "provision/windows/employee.ps1",
            destination: "C:/Windows/Temp/cr-employee.ps1"
          m.vm.provision "employee", type: "shell", path: "provision/windows/pc-2-employee.ps1",
            args: ["-Seed", LAB_SEED, "-Node", n[:name]]
        end
        m.vm.provision "exporter", type: "file", source: "provision/windows/export-events.ps1",
          destination: "C:/Windows/Temp/cr-export-events.ps1"
        m.vm.provision "telemetry", type: "shell", path: "provision/windows/telemetry.ps1",
          args: ["-Node", n[:name], "-LabIp", n[:ip], "-Role", n[:office] == "dc" ? "dc" : "pc"]
        m.vm.provision "isolate", type: "shell", run: "always", path: "provision/windows/isolate.ps1", args: ["-LabIp", n[:ip]]
        next
      end
"""
    return f"""# -*- mode: ruby -*-
# CYBER RANGE Lab Kit {kit_id}: {title.replace(chr(10), ' ')[:120]}
# Generated by CYBER RANGE. Every host of the lab is a VM; every subnet is an isolated network:
#   VirtualBox -> internal network "crk-{kit_id}-<subnet>" (no host adapter, no route out)
#   libvirt    -> isolated network (forward mode none)
# The first NIC is the Vagrant NAT adapter used only for `vagrant ssh` and for installing packages on first boot.
# provision/isolate.sh runs on every boot and blocks new outbound connections on that NAT adapter.

KIT = {_rb(kit_id)}
NODES = [
{nodes}
]
{office_head}
Vagrant.configure("2") do |config|
  config.vm.box_check_update = false
  config.vm.synced_folder ".", "/vagrant", disabled: true

  NODES.each do |n|
    config.vm.define n[:name] do |m|
      m.vm.box = n[:box]
      m.vm.hostname = n[:hostname]
      n[:nics].each do |nic|
        m.vm.network "private_network", ip: nic[:ip], netmask: nic[:mask],
          virtualbox__intnet: "crk-#{{KIT}}-#{{nic[:net]}}",
          libvirt__network_name: "crk-#{{KIT}}-#{{nic[:net]}}", libvirt__forward_mode: "none",
          libvirt__dhcp_enabled: false, libvirt__host_ip: nic[:host_ip]
      end
      m.vm.provider "virtualbox" do |vb|
        vb.name = "crk-#{{KIT}}-#{{n[:name]}}"
        vb.cpus = n[:cpus]
        vb.memory = n[:memory]
        vb.gui = false
      end
      m.vm.provider "libvirt" do |lv|
        lv.cpus = n[:cpus]
        lv.memory = n[:memory]
        lv.graphics_ip = "127.0.0.1"
      end
{office_windows}      m.vm.provision "setup", type: "shell", path: "provision/#{{n[:role]}}.sh",
        args: [n[:label], n[:router] ? "1" : "0"]
      unless n[:packages].empty?
        m.vm.provision "packages", type: "shell", path: "provision/packages.sh", args: n[:packages].split(" ")
      end
{office_linux}      m.vm.provision "isolate", type: "shell", run: "always", path: "provision/isolate.sh",
        args: [n[:routes]]
    end
  end
end
"""


PROVISION_COMMON = """#!/bin/sh
# CYBER RANGE Lab Kit provisioning (runs once, on first boot, while the NAT adapter still has internet access).
set -eu
LABEL="${1:-lab node}"
ROUTER="${2:-0}"
export DEBIAN_FRONTEND=noninteractive
if [ "$ROUTER" = "1" ]; then
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/90-cyber-range.conf
  sysctl -q -w net.ipv4.ip_forward=1
fi
have_apt() { command -v apt-get >/dev/null 2>&1; }
"""

PROVISION = {
    "base.sh": PROVISION_COMMON + """if have_apt; then apt-get -qq update || true; apt-get -qq install -y tcpdump netcat-openbsd >/dev/null || true; fi
echo "CYBER RANGE lab node ready: $LABEL"
""",
    "web.sh": PROVISION_COMMON + """if have_apt; then
  apt-get -qq update
  apt-get -qq install -y nginx tcpdump netcat-openbsd >/dev/null
  printf '<!doctype html><title>%s</title><h1>%s</h1><p>CYBER RANGE lab web server (DEMO). Isolated lab only.</p>\\n' "$LABEL" "$LABEL" > /var/www/html/index.html
  systemctl enable --now nginx
fi
echo "CYBER RANGE web node ready: $LABEL"
""",
    "redis.sh": PROVISION_COMMON + """if have_apt; then
  apt-get -qq update
  apt-get -qq install -y redis-server tcpdump netcat-openbsd >/dev/null
  # Same as the allowlisted redis image on the server: unauthenticated on purpose, for practice in an isolated lab only.
  sed -i -e 's/^bind .*/bind 0.0.0.0/' -e 's/^protected-mode .*/protected-mode no/' /etc/redis/redis.conf
  systemctl restart redis-server
fi
echo "CYBER RANGE redis node ready: $LABEL"
""",
    "isolate.sh": """#!/bin/sh
# CYBER RANGE Lab Kit isolation (runs on every boot).
# 1. Blocks new outbound connections on the Vagrant NAT adapter: the lab has no internet egress, `vagrant ssh` keeps working.
# 2. Adds routes to the lab's other subnets through the subnet gateway (the lab router/firewall), if there is one.
set -u
ROUTES="${1:-}"
NAT_IF=$(ip -4 route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -n "$NAT_IF" ] && command -v iptables >/dev/null 2>&1; then
  iptables -N CRK_EGRESS 2>/dev/null || iptables -F CRK_EGRESS
  iptables -A CRK_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A CRK_EGRESS -j DROP
  for CH in OUTPUT FORWARD; do
    iptables -C "$CH" -o "$NAT_IF" -j CRK_EGRESS 2>/dev/null || iptables -I "$CH" 1 -o "$NAT_IF" -j CRK_EGRESS
  done
elif [ -n "$NAT_IF" ]; then
  # no iptables in this box: drop the default route instead (still no egress)
  while ip -4 route del default 2>/dev/null; do :; done
fi
for R in $ROUTES; do
  NET=${R%%=*}; GW=${R#*=}
  ip -4 route replace "$NET" via "$GW" 2>/dev/null || true
done
echo "CYBER RANGE isolation applied (NAT=${NAT_IF:-none})"
""",
}


def packages_sh() -> str:
    cases = []
    for key, p in SERVER_PACKAGES.items():
        cases.append(f"    {key}) PKGS=\"{' '.join(p['apt'])}\"; SVCS=\"{' '.join(p['services'])}\" ;;")
    body = "\n".join(cases)
    return f"""#!/bin/sh
# CYBER RANGE Lab Kit: server software chosen on the Lab Kit page (runs on first provisioning, before isolate.sh).
# Ubuntu default configuration: no extra accounts, no passwords, nothing exposed outside the isolated lab networks.
# To change the selection later: edit the "packages" field of the VM in the Vagrantfile, then `vagrant reload --provision`.
set -eu
export DEBIAN_FRONTEND=noninteractive
command -v apt-get >/dev/null 2>&1 || {{ echo "This box has no apt-get; server packages skipped"; exit 0; }}
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
echo "postfix postfix/mailname string lab.local" | debconf-set-selections
apt-get -qq update
for SET in "$@"; do
  case "$SET" in
{body}
    *) echo "Unknown package set: $SET"; continue ;;
  esac
  echo "Installing $SET: $PKGS"
  apt-get -qq install -y $PKGS >/dev/null
  for S in $SVCS; do systemctl enable --now "$S" >/dev/null 2>&1 || true; done
done
echo "CYBER RANGE server packages ready: $*"
"""  # noqa: S608 (shell script text, not SQL)


# ------------------------------------------------------------------ README and helper scripts
def _node_rows(kp: dict) -> list[tuple[str, str, str, str]]:
    nets = {n["subnet_key"]: n["name"] for n in kp["networks"]}
    rows = []
    for c in kp["containers"]:
        addr = ", ".join(f"{a['ip'] or 'otomatis'} ({nets[a['subnet_key']]})" for a in c["attachments"]) or "tanpa jaringan"
        rows.append((_slug(c["node_key"]), c["label"], c["image"] + (" · mode kompatibel VM" if c.get("fallback") else ""), addr))
    for v in kp["vms"]:
        addr = ", ".join(f"{a['ip']} ({nets[a['subnet_key']]})" for a in v["nics"]) or "tanpa jaringan"
        extra = f" · paket {', '.join(v['packages'])}" if v.get("packages") else ""
        if v.get("os") == "windows" and v.get("office") == "dc":
            extra += " · Windows Server Evaluation, Active Directory asli"
        elif v.get("os") == "windows":
            extra += " · Windows 11 Evaluation, join domain, karyawan simulasi"
        elif v.get("office"):
            extra += f" · kantor ({'portal intranet' if v['office'] == 'portal' else 'karyawan simulasi'})"
        role = f" · peran {v['role']}" if v["role"] not in ("base", "windows-dc", "windows-pc") else ""
        rows.append((v["name"], v["label"], v["box"] + role + extra, addr))
    return rows


def _packages_section(kp: dict) -> str:
    chosen = [v for v in kp["vms"] if v.get("packages")]
    if not chosen:
        return ""
    rows = "\n".join(f"| `{v['name']}` | {SERVER_PACKAGES[k]['title']} | `{' '.join(SERVER_PACKAGES[k]['apt'])}` | {SERVER_PACKAGES[k]['ports']} |"
                     for v in chosen for k in v["packages"])
    return f"""
## Paket server
Dipasang otomatis oleh `provision/packages.sh` saat `vagrant up` pertama, sebelum isolasi aktif. Konfigurasi bawaan
Ubuntu: tidak ada akun atau password tambahan. Layanan hanya terjangkau dari jaringan lab yang terisolasi.

| VM | Paket | apt | Port |
|---|---|---|---|
{rows}

Untuk mengubah pilihan: edit kolom `packages` VM tersebut di `Vagrantfile` (contoh `packages: 'web-nginx db-mysql'`),
lalu jalankan `vagrant reload --provision <vm>`. Pilihan yang tersedia: {', '.join(f'`{k}`' for k in SERVER_PACKAGES)}.
Memasang paket lain secara manual: tambahkan perintah `apt-get install -y ...` di `provision/packages.sh` lalu
jalankan perintah yang sama. Langsung dari dalam VM, `apt install` tidak bisa karena internet lab diblokir.
"""


def _office_section(kp: dict) -> str:
    office = kp.get("office")
    if not office:
        return ""
    dc = next(v for v in kp["vms"] if v["office"] == "dc")
    pcs = [v for v in kp["vms"] if v["os"] == "windows" and v["office"] == "ws"]
    linux = [v["name"] for v in kp["vms"] if v["os"] == "linux" and v["office"]]
    pc_text = ""
    if pcs:
        names = ", ".join(f"`{v['name']}`" for v in pcs)
        pc_text = f"""
**PC Windows 11.** {names} memakai box `{pcs[0]['box']}` (Windows 11 Enterprise *Evaluation*, 90 hari sejak box dibuat,
{WINDOWS_PC_MB // 1024} GB RAM dan {WINDOWS_PC_CPUS} vCPU per PC, unduhan box sekitar 7 GB sekali untuk semua PC). `vagrant up` membuat `{dc['name']}` lebih dulu; setiap PC lalu
mengarahkan DNS ke DC, **join ke domain** dengan akun admin IT DEMO (`{JOIN_ADMIN}`), restart, dan mendapat karyawan simulasi
sendiri. Karyawan itu bekerja dengan **akun domain asli** lewat scheduled task "CYBER RANGE karyawan simulasi" setiap
2 menit: membuka share, mencari nama di DNS, membuka portal, `nltest`/`gpupdate`, dan sesekali salah ketik password
(4771 di DC). Password akun itu disimpan hanya oleh Task Scheduler, tidak di file mana pun. Audit policy, Sysmon, dan
ekspor event sama seperti di DC; isinya `host.auth` (4624/4625/4648 di PC) dan `host.process`.
"""
    return f"""
## Kantor dengan domain controller Windows
`{dc['name']}` adalah **Windows Server (Evaluation)** dengan Active Directory asli untuk domain `{office['domain']}`.
{('VM Ubuntu ' + ', '.join(f'`{n}`' for n in linux) + ' menjalankan portal intranet atau karyawan simulasi dan host agent yang sama seperti lab kantor di aplikasi.') if linux else ''}
{pc_text}
**Lisensi Windows.** Box `{dc['box']}` dibuat dari ISO *evaluation* resmi Microsoft (Windows Server 2022, berlaku
180 hari sejak box dibuat). Vagrant mengunduhnya langsung ke komputer Anda; kit ini tidak berisi Windows. Dengan
memakainya Anda menyetujui ketentuan evaluasi Microsoft. Bila masa evaluasi habis, jalankan `vagrant box update`
lalu `vagrant destroy -f {dc['name']}` dan `vagrant up {dc['name']}`.

**Kebutuhan tambahan.** Hanya **VirtualBox** (box Windows tidak tersedia untuk libvirt). DC butuh {WINDOWS_DC_MB // 1024} GB RAM
dan {WINDOWS_DC_CPUS} vCPU, unduhan box sekitar 6 sampai 8 GB, dan `vagrant up` pertama sekitar 20 sampai 40 menit
(memasang AD DS, restart, membuat organisasi DEMO, memasang Sysmon dari download.sysinternals.com).

**Apa yang dibuat di domain.** OU `Karyawan` dan `Grup`, grup departemen, enam karyawan DEMO, share `Umum` dan
`Keuangan` berisi dokumen DEMO, record DNS untuk host lab, audit policy (logon, Kerberos, validasi kredensial,
manajemen akun dan grup, pembuatan proses) dan Sysmon.

**Password.** Saat `vagrant up` pertama, Vagrantfile membuat file `.lab-seed` acak di folder ini. Password karyawan
DEMO diturunkan dari seed itu di dalam VM, sama di DC dan di PC karyawan, dan tidak ditampilkan. Password
Administrator domain dan DSRM dibuat acak sekali pakai dan tidak disimpan. Vagrant mengelola VM Windows dengan akun
bawaan box `vagrant` (setelah promosi menjadi akun domain dengan hak admin). Itu akun pengelolaan lab, bukan bagian
skenario. Hapus `.lab-seed` hanya bersama `vagrant destroy -f`.

**Telemetri ke SIEM aplikasi.**
1. Di CYBER RANGE buka **SIEM & Analisis Log → Sumber log**, tambah sumber jenis **json** (misalnya "Lab Kit kantor").
2. Simpan file konfigurasi yang diberikan aplikasi sebagai `cr-shipper.env` di folder kit ini. File itu berisi
   ingest key: jangan dibagikan. Kit ini sendiri tidak pernah berisi key.
3. Jalankan `kirim-ke-siem.bat` (Windows) atau `sh kirim-ke-siem.sh` (Linux/macOS, butuh python3). Skrip mengirim
   baris baru dari folder `telemetry/` setiap 15 detik.

| File | Dari | Isi |
|---|---|---|
| `telemetry/{dc['name']}.jsonl` | Event Log Windows di DC (diekspor tiap menit) | `ad.auth` 4624/4625/4768/4771/4776, `ad.change` 4720/4728/4732/4756, `host.process` Sysmon 1 atau 4688 |
{''.join(f"| `telemetry/{v['name']}.jsonl` | Event Log Windows 11 di PC (diekspor tiap menit) | `host.auth` 4624/4625/4648, `host.process` Sysmon 1 atau 4688 |" + chr(10) for v in pcs)}| `telemetry/<pc atau portal>.jsonl` | host agent di VM Ubuntu | `host.*`, `web.access`, `web.auth` |

Rule CR-AD-001 dan CR-AD-002 di aplikasi menghitung login gagal dari Windows (4771, 4776, 4625) maupun dari lab kantor
di aplikasi.
"""


def readme(kp: dict, kit_id: str, title: str, source: str) -> str:
    t = kp["totals"]
    rows = "\n".join(f"| `{a}` | {b} | {c} | {d} |" for a, b, c, d in _node_rows(kp))
    subnets = "\n".join(f"| {n['name']} | {n['cidr']} | {n.get('gateway') or '-'} |" for n in kp["networks"])
    skipped = "\n".join(f"* {s['label']}: tidak dijalankan ({s['reason']})" for s in kp["skipped"]) or "* (tidak ada)"
    if kp["format"] == "docker":
        need = ("* **Docker Desktop** (Windows/macOS) atau **Docker Engine + Docker Compose v2** (Linux).\n"
                f"* RAM kosong kira-kira **{max(1, round(t['memory_mb'] / 1024, 1))} GB** dan koneksi internet untuk mengunduh image pertama kali.")
        run = """1. Ekstrak ZIP ini ke folder mana saja.
2. Windows: klik dua kali `mulai.bat`. Linux/macOS: jalankan `sh mulai.sh`.
   (Sama dengan perintah `docker compose up -d`.)
3. Lihat node yang berjalan: `docker compose ps`.
4. Masuk ke shell sebuah node: `docker compose exec <node> sh` (contoh: `docker compose exec web-1 sh`).
5. Selesai: `berhenti.bat` / `sh berhenti.sh` (sama dengan `docker compose down`). Semua container dan jaringan lab dihapus."""
        notes = """* Setiap subnet adalah jaringan Docker **internal**: tidak ada akses internet, tidak ada NAT, dan komputer Anda tidak mendapat alamat di jaringan lab.
* Container berjalan tanpa hak istimewa (`cap_drop: ALL`, `no-new-privileges`, batas RAM/CPU/PID), sama seperti di server.
* Node bertipe VM dijalankan sebagai container (mode kompatibel). Untuk VM sungguhan, unduh kit format **Vagrant**.
* Jika muncul error `Pool overlaps with other one on this network`, subnet lab bentrok dengan jaringan lain di komputer Anda.
  Hapus lab lama dengan `docker compose down`, atau ubah CIDR subnet di editor Network lalu unduh ulang kit."""
    else:
        need = ("* **Vagrant 2.4+** dan **VirtualBox 7** (Windows/macOS/Linux), atau **libvirt + plugin vagrant-libvirt** (Linux).\n"
                f"* RAM kosong kira-kira **{max(1, round(t['memory_mb'] / 1024, 1))} GB** dan {t['cpus']} vCPU; ruang disk ±3 GB per box.\n"
                "* Internet saat `vagrant up` pertama kali (mengunduh box dan memasang paket). Setelah itu lab terisolasi.")
        run = """1. Ekstrak ZIP ini ke folder mana saja.
2. Windows: klik dua kali `mulai.bat`. Linux/macOS: jalankan `sh mulai.sh`.
   (Sama dengan `vagrant up`. Untuk libvirt: `vagrant up --provider=libvirt`.)
3. Lihat status VM: `vagrant status`.
4. Masuk ke sebuah VM: `vagrant ssh <node>` (contoh: `vagrant ssh web-1`). Gunakan `sudo -i` untuk menjadi root di dalam VM.
5. Matikan sementara: `berhenti.bat` / `sh berhenti.sh` (`vagrant halt`). Hapus semua VM: `hapus.bat` / `sh hapus.sh` (`vagrant destroy -f`).
6. Untuk memasang ulang paket: `vagrant reload --provision`."""
        notes = """* Setiap subnet menjadi **internal network** VirtualBox: tidak ada host-only adapter, jadi komputer Anda tidak tersambung ke jaringan lab. Di libvirt, subnet menjadi jaringan terisolasi (`forward mode none`): komputer Anda mendapat satu alamat di sana, tetapi tidak ada forwarding ke luar.
* Adapter pertama adalah NAT milik Vagrant untuk `vagrant ssh` dan pemasangan paket. Skrip `provision/isolate.sh` berjalan di setiap boot dan memblokir koneksi keluar baru lewat adapter itu, sehingga lab tidak punya akses internet.
* Node dengan gateway mendapat route ke subnet lain lewat router/firewall lab, dan router/firewall mendapat `ip_forward=1`.
* Box yang dipakai hanya yang diizinkan admin server (`CR_KIT_VAGRANT_BOXES`).
* Jalankan beberapa VM saja jika RAM terbatas, misalnya `vagrant up fw-1 web-1`."""
    return f"""# Lab Kit CYBER RANGE: {title}

Kit `{kit_id}` · format **{'Docker Compose' if kp['format'] == 'docker' else 'Vagrant (VM)'}** · sumber: {source}

Lab ini berjalan **di komputer Anda sendiri**, bukan di server CYBER RANGE. Isinya hanya rancangan lab
(host, subnet, dan image yang diizinkan). Kit ini tidak berisi password, token, alamat server, atau flag CTF.

## Kebutuhan
{need}
* Total: {t['nodes']} node, {t['networks']} subnet, {t['cpus']} CPU, {t['memory_mb']} MB RAM.

## Cara menjalankan
{run}

## Node
| Nama | Label | Image / box | Alamat |
|---|---|---|---|
{rows}

## Subnet
| Nama | CIDR | Gateway |
|---|---|---|
{subnets}

Node yang tidak dijalankan:
{skipped}
{_packages_section(kp)}{_office_section(kp)}
## Keamanan
{notes}
* Lab ini adalah data **DEMO** untuk latihan. Jangan sambungkan lab ke jaringan produksi dan jangan pakai teknik dari lab terhadap sistem tanpa izin.
* Hasil di lab lokal **tidak dinilai** oleh server. Submit flag CTF tetap lewat halaman CTF di CYBER RANGE.

## Berkas
* `{'docker-compose.yml' if kp['format'] == 'docker' else 'Vagrantfile'}`: definisi lab.
{'* `provision/`: skrip pemasangan dan isolasi VM.' + chr(10) if kp['format'] == 'vagrant' else ''}* `topology.json`: topologi asli. Bisa diimpor kembali di menu Network → Import.
* `mulai`, `berhenti`{', `hapus`' if kp['format'] == 'vagrant' else ''}: pintasan perintah untuk Windows (`.bat`) dan Linux/macOS (`.sh`).
"""


def _scripts(fmt: str) -> dict[str, str]:
    if fmt == "docker":
        cmds = {"mulai": ("docker compose up -d", "docker compose ps"), "berhenti": ("docker compose down",)}
    else:
        cmds = {"mulai": ("vagrant up", "vagrant status"), "berhenti": ("vagrant halt",), "hapus": ("vagrant destroy -f",)}
    out = {}
    for name, cc in cmds.items():
        out[f"{name}.sh"] = "#!/bin/sh\ncd \"$(dirname \"$0\")\" || exit 1\n" + "\n".join(cc) + "\n"
        out[f"{name}.bat"] = "@echo off\r\ncd /d \"%~dp0\"\r\n" + "\r\n".join(cc) + "\r\npause\r\n"
    return out


def _office_common():
    """The office lab's own constants (employees, departments, share documents): one source for images and kits."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("cr_office_common", ASSETS / "office_lab" / "common.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ps(s: str) -> str:
    """PowerShell single-quoted literal."""
    return "'" + str(s).replace("'", "''") + "'"


def windows_files(kp: dict) -> dict[str, str]:
    office = kp["office"]
    dc = next(v for v in kp["vms"] if v["office"] == "dc")
    c = _office_common()
    employees = "\n".join("    @{ User = %s; Name = %s; First = %s; Last = %s; Dept = %s }" % (
        _ps(u), _ps(n), _ps(n.partition(" ")[0]), _ps(n.partition(" ")[2] or n), _ps(d)) for u, n, d in c.EMPLOYEES)
    docs = "\n".join("    %s = @{ %s }" % (_ps(share), "; ".join(f"{_ps(f)} = {_ps(t)}" for f, t in files.items()))
                      for share, files in c.SHARE_DOCS.items())
    records = "\n".join(f"    {_ps(v['hostname'].split('.')[0].lower())} = {_ps(v['nics'][0]['ip'])}"
                         for v in kp["vms"] if v["nics"] and v is not dc)
    users = ", ".join(_ps(u) for u, _, _ in c.EMPLOYEES)
    depts = ", ".join(_ps(d) for _, _, d in c.EMPLOYEES)
    values = {"@@DOMAIN@@": office["domain"], "@@NETBIOS@@": office["domain"].split(".")[0].upper()[:15], "@@LAB_IP@@": office["dc_ip"],
              "@@DC_IP@@": office["dc_ip"], "@@DC_HOST@@": office["dc_host"], "@@EMPLOYEES@@": employees,
              "@@USERS@@": users, "@@DEPTS@@": depts, "@@GROUPS@@": ", ".join(_ps(g) for g in c.GROUPS),
              "@@DOCS@@": docs, "@@RECORDS@@": records, "@@JOIN_ADMIN@@": JOIN_ADMIN}
    names = WINDOWS_DC_FILES + WINDOWS_COMMON_FILES
    if any(v["os"] == "windows" and v["office"] == "ws" for v in kp["vms"]):
        names += WINDOWS_PC_FILES
    out = {}
    for name in names:
        text = (ASSETS / "kit_windows" / name).read_text()
        for k, v in values.items():
            text = text.replace(k, v)
        out[f"provision/windows/{name}"] = text
    return out


def office_files(kp: dict) -> dict[str, str]:
    files = {f"provision/office/{f}": (ASSETS / "office_lab" / f).read_text() for f in OFFICE_FILES}
    files["provision/office.sh"] = (ASSETS / "kit_windows" / "office.sh").read_text()
    files["kirim-ke-siem.py"] = (ASSETS / "kit_windows" / "kirim-ke-siem.py").read_text()
    files["kirim-ke-siem.ps1"] = (ASSETS / "kit_windows" / "kirim-ke-siem.ps1").read_text()
    files["kirim-ke-siem.bat"] = ("@echo off\r\ncd /d \"%~dp0\"\r\n"
                                  "powershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0kirim-ke-siem.ps1\"\r\npause\r\n")
    files["kirim-ke-siem.sh"] = "#!/bin/sh\ncd \"$(dirname \"$0\")\" || exit 1\nexec python3 kirim-ke-siem.py\n"
    files["telemetry/BACA-SAYA.txt"] = ("Folder ini diisi oleh VM lab: satu file <node>.jsonl per node (event host, login domain, portal).\n"
                                        "kirim-ke-siem mengirimnya ke SIEM aplikasi CYBER RANGE Anda.\n")
    if any(v["os"] == "windows" for v in kp["vms"]):
        files.update(windows_files(kp))
    return files


def kit_id_for(doc: dict, fmt: str, packages: dict[str, list[str]] | None = None, windows_dc: bool = False,
               windows_pcs: list[str] | None = None) -> str:
    extra = ((json.dumps(packages, sort_keys=True) if packages else "") + ("|windows-dc" if windows_dc else "")
             + ("|windows-pc:" + ",".join(sorted(set(windows_pcs))) if windows_pcs else ""))
    return hashlib.sha256((fmt + json.dumps(doc, sort_keys=True, default=str) + extra).encode()).hexdigest()[:6]


def build_zip(doc: dict, images: list[dict], *, fmt: str, title: str, source: str, boxes: dict[str, str],
              packages: dict[str, list[str]] | None = None, windows_dc: bool = False,
              windows_box: str = DEFAULT_WINDOWS_DC_BOX, windows_pcs: list[str] | None = None,
              windows_pc_box: str = DEFAULT_WINDOWS_PC_BOX) -> tuple[bytes, dict]:
    kp = plan_for(doc, images, fmt, boxes, packages, windows_dc, windows_box, windows_pcs, windows_pc_box)
    kid = kit_id_for(doc, fmt, packages, windows_dc, windows_pcs)
    files: dict[str, str] = {"README.md": readme(kp, kid, title, source),
                             "topology.json": json.dumps(doc, indent=2, ensure_ascii=False, default=str) + "\n"}
    if fmt == "docker":
        files["docker-compose.yml"] = (f"# CYBER RANGE Lab Kit {kid}: {title[:120]}\n# Generated by CYBER RANGE. Run: docker compose up -d\n"
                                       + yaml.safe_dump(compose_doc(kp, kid), sort_keys=False, allow_unicode=True))
    else:
        files["Vagrantfile"] = vagrantfile(kp, kid, title)
        used = {v["role"] for v in kp["vms"]} | {"isolate"}
        files.update({f"provision/{k}": v for k, v in PROVISION.items() if k[:-3] in used})
        if any(v["packages"] for v in kp["vms"]):
            files["provision/packages.sh"] = packages_sh()
        if kp.get("office"):
            files.update(office_files(kp))
    files.update(_scripts(fmt))
    root = f"cyber-range-kit-{_slug(title, 40)}-{kid}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(f"{root}/{name}", date_time=ZIP_DATE)
            info.external_attr = (0o755 if name.endswith(".sh") or name == "kirim-ke-siem.py" else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, files[name])
    meta = {"kit_id": kid, "format": fmt, "root": root, "totals": kp["totals"], "files": sorted(files)}
    return buf.getvalue(), meta


def preview(doc: dict, images: list[dict], *, fmt: str, boxes: dict[str, str], packages: dict[str, list[str]] | None = None,
            windows_dc: bool = False, windows_box: str = DEFAULT_WINDOWS_DC_BOX, windows_pcs: list[str] | None = None,
            windows_pc_box: str = DEFAULT_WINDOWS_PC_BOX) -> dict:
    """What a kit would contain, without building it (for the download dialog)."""
    kp = plan_for(doc, images, fmt, boxes, packages, windows_dc, windows_box, windows_pcs, windows_pc_box)
    by = {v["name"]: v for v in kp["vms"]}
    return {"format": fmt, "totals": kp["totals"], "skipped": kp["skipped"],
            "nodes": [{"name": a, "label": b, "runs_as": c, "addresses": d, "packages": by.get(a, {}).get("packages", []),
                       "office": by.get(a, {}).get("office") or None, "os": by.get(a, {}).get("os", "linux")}
                      for a, b, c, d in _node_rows(kp)],
            "windows_dc": {"available": fmt == "vagrant" and sum(office_role(v.get("image")) == "dc" for v in kp["vms"]) == 1,
                           "selected": windows_dc, "box": windows_box, "memory_mb": WINDOWS_DC_MB},
            "windows_pc": {"available": bool(windows_dc) and any(v["office"] == "ws" for v in kp["vms"]),
                           "selected": sorted(v["name"] for v in kp["vms"] if v["os"] == "windows" and v["office"] == "ws"),
                           "box": windows_pc_box, "memory_mb": WINDOWS_PC_MB}}
