"""Turn a topology document into a deterministic Docker deployment plan.

Rules
* Each IPv4 subnet becomes an *internal* bridge network (no route off-host: default-deny egress).
* `switch` nodes are realised by the bridge itself; `internet` nodes are never deployed (no egress by policy).
* `vm` nodes go to the VM adapter when the host supports it, otherwise run as containers (compatible mode).
* Every other node becomes one hardened container from the image allowlist.
"""
import ipaddress
import re

NOT_DEPLOYED = {"internet": "Internet is simulated only; labs have no egress (default-deny)",
                "switch": "Realised by the subnet's isolated bridge network"}
ROUTING = {"router", "firewall"}
KEEPALIVE = ["sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]


class PlanError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def _slug(s: str, n: int = 40) -> str:
    return re.sub(r"[^a-z0-9-]", "-", s.lower()).strip("-")[:n] or "x"


MIN_PREFIX = 16


def _top_hosts(net, n: int) -> list[str]:
    """The highest n usable host addresses, without materialising the whole network."""
    last = int(net.broadcast_address) - 1
    first = int(net.network_address) + 1
    return [str(ipaddress.ip_address(i)) for i in range(last, max(first, last - n + 1) - 1, -1)]


def pick_image(node: dict, images: list[dict]) -> dict | None:
    wanted = (node.get("properties") or {}).get("image")
    usable = [i for i in images if i["is_enabled"] and node["type"] in i["node_types"]]
    if wanted:
        return next((i for i in usable if i["reference"] == wanted), None)
    return usable[0] if usable else None


def build_plan(doc: dict, images: list[dict], *, vm_supported: bool = False, vm_templates: list[str] | None = None) -> dict:
    vm_templates = list(vm_templates or [])
    problems: list[str] = []
    networks, containers, vms, skipped = [], [], [], []
    used_ips: dict[str, set[str]] = {}
    for n in doc["nodes"]:
        for i in n.get("interfaces", []):
            if i.get("subnet") and i.get("ip"):
                used_ips.setdefault(i["subnet"], set()).add(i["ip"])

    for s in doc["subnets"]:
        try:
            net = ipaddress.ip_network(s["cidr"], strict=True)
        except ValueError:
            problems.append(f"Subnet {s['name']}: invalid CIDR {s['cidr']}")
            continue
        if net.version != 4:
            problems.append(f"Subnet {s['name']}: only IPv4 subnets can be deployed")
            continue
        if net.prefixlen > 29:
            problems.append(f"Subnet {s['name']}: /{net.prefixlen} is too small to deploy (max /29)")
            continue
        if net.prefixlen < MIN_PREFIX:
            # A lab subnet never needs more than 65k addresses; larger ones only cost memory and scan time.
            problems.append(f"Subnet {s['name']}: /{net.prefixlen} is too large to deploy (min /{MIN_PREFIX})")
            continue
        # Docker assigns the bridge gateway to the host side; pick the highest free host address for it
        # so the topology's own gateway IP stays available for the router/firewall container.
        taken = used_ips.get(s["key"], set()) | ({s["gateway"]} if s.get("gateway") else set())
        gw = next((h for h in _top_hosts(net, 64) if h not in taken), None)
        if gw is None:
            problems.append(f"Subnet {s['name']}: no free address left for the isolated bridge")
            continue
        networks.append({"subnet_key": s["key"], "name": s["name"], "cidr": str(net), "bridge_ip": gw, "gateway": s.get("gateway")})
    deployable = {n["subnet_key"]: n for n in networks}

    for node in doc["nodes"]:
        t = node["type"]
        if t in NOT_DEPLOYED:
            skipped.append({"node_key": node["key"], "label": node["label"], "reason": NOT_DEPLOYED[t]})
            continue
        if t == "vm" and vm_supported and (node.get("properties") or {}).get("runtime") != "container":
            props = node.get("properties") or {}
            tmpl = props.get("vm_template") or (vm_templates[0] if vm_templates else None)
            if not tmpl or tmpl not in vm_templates:
                problems.append(f"Node {node['label']}: VM template '{tmpl or '-'}' is not allowlisted on the VM host"
                                + (f" (available: {', '.join(vm_templates)})" if vm_templates else " (none configured)"))
                continue
            vcpus, vmem = int(props.get("cpus") or 1), int(props.get("memory_mb") or 1024)
            if not (1 <= vcpus <= 8) or not (256 <= vmem <= 16384):
                problems.append(f"Node {node['label']}: a VM needs 1-8 vCPUs and 256-16384 MB memory")
                continue
            nics = []
            for itf in node.get("interfaces", []):
                sk = itf.get("subnet")
                if sk in deployable and not any(n["subnet_key"] == sk for n in nics):
                    nics.append({"subnet_key": sk, "ip": itf.get("ip") or None, "interface": itf["name"]})
            vms.append({"node_key": node["key"], "label": node["label"], "slug": _slug(node["key"], 30), "template": tmpl,
                        "vcpus": vcpus, "memory_mb": vmem, "nics": nics})
            continue
        img = pick_image(node, images)
        if img is None:
            want = (node.get("properties") or {}).get("image")
            problems.append(f"Node {node['label']}: " + (f"image '{want}' is not allowlisted for type {t}" if want else f"no allowlisted image for type {t}"))
            continue
        attachments = []
        for itf in node.get("interfaces", []):
            sk = itf.get("subnet")
            if not sk or sk not in deployable:
                continue
            ip = itf.get("ip")
            if ip and ip == deployable[sk]["bridge_ip"]:
                problems.append(f"Node {node['label']}: {ip} collides with the bridge address")
            if any(a["subnet_key"] == sk for a in attachments):
                continue  # one attachment per subnet
            attachments.append({"subnet_key": sk, "ip": ip or None, "interface": itf["name"]})
        props = node.get("properties") or {}
        cpus = float(props.get("cpus") or img["default_cpus"])
        mem = int(props.get("memory_mb") or img["default_memory_mb"])
        if not (0.05 <= cpus <= 4):
            problems.append(f"Node {node['label']}: cpus must be between 0.05 and 4")
        if not (16 <= mem <= 8192):
            problems.append(f"Node {node['label']}: memory_mb must be between 16 and 8192")
        hostname = _slug(node.get("hostname") or node["key"], 63)
        containers.append({
            "node_key": node["key"], "label": node["label"], "type": t, "hostname": hostname, "slug": _slug(node["key"], 30),
            "image": img["reference"], "command": img.get("command"), "tmpfs": img.get("tmpfs") or [], "cap_add": img.get("cap_add") or [],
            "cpus": cpus, "memory_mb": mem, "attachments": attachments, "ip_forward": t in ROUTING,
            "fallback": "vm-as-container" if t == "vm" else None,
        })
    if not containers and not vms:
        problems.append("Nothing to deploy: add at least one server, workstation, router, firewall, database, VM, container or sensor")
    if problems:
        raise PlanError(problems)
    return {
        "networks": networks, "containers": containers, "vms": vms, "skipped": skipped,
        "totals": {"containers": len(containers), "cpus": round(sum(c["cpus"] for c in containers) + sum(v["vcpus"] for v in vms), 2),
                   "memory_mb": sum(c["memory_mb"] for c in containers) + sum(v["memory_mb"] for v in vms), "networks": len(networks), "vms": len(vms)},
    }
