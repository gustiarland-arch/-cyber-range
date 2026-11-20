"""Server-side topology validation: structure (blocks save) and semantics (reported, stored as status)."""
import ipaddress
from collections import Counter, defaultdict

from app.network.schemas import Issue, TopologyDoc

ROUTING = {"router", "firewall"}
L2 = {"switch"}
INFRA = ROUTING | L2


def structural_errors(doc: TopologyDoc) -> list[Issue]:
    """Referential integrity problems. A document with these cannot be persisted."""
    out: list[Issue] = []

    def dupes(kind: str, keys: list[str]):
        for k, n in Counter(keys).items():
            if n > 1:
                out.append(Issue(severity="error", code="duplicate_key", message=f"Duplicate {kind} key '{k}'", ref={kind: k}))

    zones = [z.key for z in doc.zones]
    subnets = [s.key for s in doc.subnets]
    nodes = [n.key for n in doc.nodes]
    dupes("zone", zones)
    dupes("subnet", subnets)
    dupes("node", nodes)
    dupes("link", [link.key for link in doc.links])
    zs, ss, ns = set(zones), set(subnets), set(nodes)
    for s in doc.subnets:
        if s.zone and s.zone not in zs:
            out.append(Issue(severity="error", code="unknown_zone", message=f"Subnet '{s.name}' references unknown zone '{s.zone}'", ref={"subnet": s.key}))
    for n in doc.nodes:
        if n.zone and n.zone not in zs:
            out.append(Issue(severity="error", code="unknown_zone", message=f"Node '{n.label}' references unknown zone '{n.zone}'", ref={"node": n.key}))
        for k, c in Counter(i.name for i in n.interfaces).items():
            if c > 1:
                out.append(Issue(severity="error", code="duplicate_interface", message=f"Node '{n.label}' has interface '{k}' twice", ref={"node": n.key}))
        for i in n.interfaces:
            if i.subnet and i.subnet not in ss:
                out.append(Issue(severity="error", code="unknown_subnet", message=f"Interface {n.label}/{i.name} references unknown subnet '{i.subnet}'", ref={"node": n.key}))
    for link in doc.links:
        for end in (link.source, link.target):
            if end not in ns:
                out.append(Issue(severity="error", code="dangling_link", message=f"Link '{link.key}' references unknown node '{end}'", ref={"link": link.key}))
    return out


def semantic_issues(doc: TopologyDoc) -> list[Issue]:
    out: list[Issue] = []
    E = lambda code, msg, ref: out.append(Issue(severity="error", code=code, message=msg, ref=ref))  # noqa: E731
    W = lambda code, msg, ref: out.append(Issue(severity="warning", code=code, message=msg, ref=ref))  # noqa: E731

    nets: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
    for s in doc.subnets:
        try:
            net = ipaddress.ip_network(s.cidr, strict=True)
        except ValueError as e:
            E("invalid_cidr", f"Subnet '{s.name}': invalid CIDR {s.cidr} ({e})", {"subnet": s.key})
            continue
        nets[s.key] = net
        if s.gateway:
            try:
                gw = ipaddress.ip_address(s.gateway)
                if gw not in net:
                    E("gateway_outside_subnet", f"Subnet '{s.name}': gateway {gw} is not inside {net}", {"subnet": s.key})
                elif net.num_addresses > 2 and gw in (net.network_address, net.broadcast_address):
                    E("gateway_reserved", f"Subnet '{s.name}': gateway {gw} is the network/broadcast address", {"subnet": s.key})
            except ValueError:
                E("invalid_gateway", f"Subnet '{s.name}': invalid gateway '{s.gateway}'", {"subnet": s.key})
    keys = list(nets)
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            if nets[a].version == nets[b].version and nets[a].overlaps(nets[b]):
                E("subnet_overlap", f"Subnets {nets[a]} and {nets[b]} overlap", {"subnet": b})

    sub_by_key = {s.key: s for s in doc.subnets}
    used: dict[tuple[str, str], str] = {}
    node_subnets: dict[str, set[str]] = defaultdict(set)
    for n in doc.nodes:
        for itf in n.interfaces:
            if itf.subnet:
                node_subnets[n.key].add(itf.subnet)
            if not itf.ip:
                continue
            try:
                ip = ipaddress.ip_address(itf.ip)
            except ValueError:
                E("invalid_ip", f"{n.label}/{itf.name}: invalid IP '{itf.ip}'", {"node": n.key})
                continue
            if not itf.subnet:
                W("ip_without_subnet", f"{n.label}/{itf.name}: IP {ip} is not attached to a subnet", {"node": n.key})
                continue
            net = nets.get(itf.subnet)
            if net is None:
                continue
            if ip not in net:
                E("ip_outside_subnet", f"{n.label}/{itf.name}: {ip} is outside {net}", {"node": n.key})
                continue
            if net.num_addresses > 2 and ip in (net.network_address, net.broadcast_address):
                E("ip_reserved", f"{n.label}/{itf.name}: {ip} is the network/broadcast address of {net}", {"node": n.key})
            gw = sub_by_key[itf.subnet].gateway
            if gw and str(ip) == gw and n.type not in ROUTING:
                E("ip_is_gateway", f"{n.label}/{itf.name}: {ip} is the subnet gateway but node is a {n.type}", {"node": n.key})
            k = (itf.subnet, str(ip))
            if k in used and used[k] != n.key:
                E("duplicate_ip", f"IP {ip} is assigned to both '{used[k]}' and '{n.key}'", {"node": n.key})
            used.setdefault(k, n.key)

    by_key = {n.key: n for n in doc.nodes}
    degree: Counter = Counter()
    pairs: Counter = Counter()
    zone_kind = {z.key: z.kind for z in doc.zones}
    for link in doc.links:
        if link.source not in by_key or link.target not in by_key:
            continue
        a, b = by_key[link.source], by_key[link.target]
        if a.key == b.key:
            E("self_link", f"Link '{link.key}' connects '{a.label}' to itself", {"link": link.key})
            continue
        degree[a.key] += 1
        degree[b.key] += 1
        pairs[tuple(sorted((a.key, b.key)))] += 1
        if a.zone != b.zone and a.type not in INFRA and b.type not in INFRA:
            W("cross_zone_direct", f"'{a.label}' and '{b.label}' are in different zones without a router/firewall between them", {"link": link.key})
        kinds = {zone_kind.get(a.zone or ""), zone_kind.get(b.zone or "")}
        types = {a.type, b.type}
        if "internet" in types and "firewall" not in types and ({"internal", "restricted", "management"} & kinds):
            E("internet_to_internal", f"Internet node is linked directly into a protected zone via '{link.key}' (add a firewall)", {"link": link.key})
        if a.type not in INFRA and b.type not in INFRA and node_subnets[a.key] and node_subnets[b.key] \
                and not (node_subnets[a.key] & node_subnets[b.key]):
            W("no_common_subnet", f"'{a.label}' and '{b.label}' are linked but share no subnet", {"link": link.key})
    for pair, c in pairs.items():
        if c > 1:
            W("duplicate_link", f"{c} links between '{pair[0]}' and '{pair[1]}'", {"node": pair[0]})
    for n in doc.nodes:
        if degree[n.key] == 0 and len(doc.nodes) > 1:
            W("isolated_node", f"'{n.label}' has no connections", {"node": n.key})
        if n.type not in ("internet", "switch") and not n.interfaces:
            W("no_interfaces", f"'{n.label}' has no network interfaces configured", {"node": n.key})
    return out


def validate(doc: TopologyDoc) -> list[Issue]:
    return structural_errors(doc) + semantic_issues(doc)


def status_of(issues: list[Issue]) -> tuple[str, int, int]:
    e = sum(i.severity == "error" for i in issues)
    w = sum(i.severity == "warning" for i in issues)
    return ("invalid" if e else "warnings" if w else "valid"), e, w
