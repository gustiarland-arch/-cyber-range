"""Built-in starter topologies. Labelled DEMO: they are examples, not discovered infrastructure."""

TEMPLATES: dict[str, dict] = {
    "blank": {"title": "Blank topology", "description": "Empty canvas.", "doc": {"zones": [], "subnets": [], "nodes": [], "links": []}},
    "corporate-dmz": {
        "title": "Corporate DMZ (DEMO)",
        "description": "Internet edge firewall, DMZ web tier, internal LAN, database segment and SOC sensor.",
        "doc": {
            "zones": [
                {"key": "z-inet", "name": "Internet", "kind": "internet", "color": "#64748b", "position": {"x": -40, "y": 40}, "size": {"w": 220, "h": 200}},
                {"key": "z-dmz", "name": "DMZ", "kind": "dmz", "color": "#f59e0b", "position": {"x": 420, "y": -60}, "size": {"w": 420, "h": 220}},
                {"key": "z-lan", "name": "Corporate LAN", "kind": "internal", "color": "#3b82f6", "position": {"x": 420, "y": 220}, "size": {"w": 420, "h": 240}},
                {"key": "z-data", "name": "Data", "kind": "restricted", "color": "#a855f7", "position": {"x": 900, "y": 220}, "size": {"w": 260, "h": 240}},
            ],
            "subnets": [
                {"key": "s-dmz", "name": "DMZ", "cidr": "172.16.10.0/24", "gateway": "172.16.10.1", "vlan": 10, "zone": "z-dmz"},
                {"key": "s-lan", "name": "LAN", "cidr": "10.10.0.0/24", "gateway": "10.10.0.1", "vlan": 20, "zone": "z-lan"},
                {"key": "s-data", "name": "Data", "cidr": "10.20.0.0/24", "gateway": "10.20.0.1", "vlan": 30, "zone": "z-data"},
            ],
            "nodes": [
                {"key": "inet", "type": "internet", "label": "Internet", "zone": "z-inet", "position": {"x": 20, "y": 110}},
                {"key": "fw-edge", "type": "firewall", "label": "Edge Firewall", "hostname": "fw-edge", "os": "pfSense", "position": {"x": 260, "y": 110},
                 "interfaces": [{"name": "dmz0", "subnet": "s-dmz", "ip": "172.16.10.1"}, {"name": "lan0", "subnet": "s-lan", "ip": "10.10.0.1"},
                                {"name": "data0", "subnet": "s-data", "ip": "10.20.0.1"}]},
                {"key": "web-1", "type": "server", "label": "Web Server", "hostname": "web-1", "os": "Ubuntu 24.04", "zone": "z-dmz", "position": {"x": 460, "y": -10},
                 "properties": {"image": "nginx:1.27-alpine", "services": [{"port": 80, "proto": "tcp", "name": "http"}]}, "interfaces": [{"name": "eth0", "subnet": "s-dmz", "ip": "172.16.10.10"}]},
                {"key": "mail-1", "type": "server", "label": "Mail Relay", "hostname": "mail-1", "os": "Debian 12", "zone": "z-dmz", "position": {"x": 660, "y": -10},
                 "properties": {"services": [{"port": 25, "proto": "tcp", "name": "smtp"}]}, "interfaces": [{"name": "eth0", "subnet": "s-dmz", "ip": "172.16.10.20"}]},
                {"key": "sw-lan", "type": "switch", "label": "Core Switch", "zone": "z-lan", "position": {"x": 560, "y": 260}},
                {"key": "ws-1", "type": "workstation", "label": "Analyst WS", "hostname": "ws-1", "os": "Windows 11", "zone": "z-lan", "position": {"x": 460, "y": 380},
                 "interfaces": [{"name": "eth0", "subnet": "s-lan", "ip": "10.10.0.21"}]},
                {"key": "ws-2", "type": "workstation", "label": "Finance WS", "hostname": "ws-2", "os": "Windows 11", "zone": "z-lan", "position": {"x": 660, "y": 380},
                 "interfaces": [{"name": "eth0", "subnet": "s-lan", "ip": "10.10.0.22"}]},
                {"key": "db-1", "type": "database", "label": "Customer DB", "hostname": "db-1", "os": "MySQL 8.4", "zone": "z-data", "position": {"x": 980, "y": 300},
                 "properties": {"services": [{"port": 3306, "proto": "tcp", "name": "mysql"}]}, "interfaces": [{"name": "eth0", "subnet": "s-data", "ip": "10.20.0.10"}]},
                {"key": "ids-1", "type": "sensor", "label": "IDS Sensor", "hostname": "ids-1", "os": "Suricata", "zone": "z-lan", "position": {"x": 760, "y": 260},
                 "interfaces": [{"name": "mon0", "subnet": "s-lan", "ip": "10.10.0.5"}]},
            ],
            "links": [
                {"key": "l1", "source": "inet", "target": "fw-edge", "kind": "fiber", "bandwidth_mbps": 1000},
                {"key": "l2", "source": "fw-edge", "target": "web-1"},
                {"key": "l3", "source": "fw-edge", "target": "mail-1"},
                {"key": "l4", "source": "fw-edge", "target": "sw-lan", "bandwidth_mbps": 10000},
                {"key": "l5", "source": "sw-lan", "target": "ws-1"},
                {"key": "l6", "source": "sw-lan", "target": "ws-2"},
                {"key": "l7", "source": "sw-lan", "target": "ids-1", "label": "SPAN"},
                {"key": "l8", "source": "fw-edge", "target": "db-1"},
            ],
        },
    },
}


def _z(key, name, kind, color, x, y, w, h):
    return {"key": key, "name": name, "kind": kind, "color": color, "position": {"x": x, "y": y}, "size": {"w": w, "h": h}}


def _n(key, type_, label, zone, x, y, ifaces=(), host=None, os=None, image=None, services=None):
    node = {"key": key, "type": type_, "label": label, "position": {"x": x, "y": y}}
    if zone:
        node["zone"] = zone
    if host:
        node["hostname"] = host
    if os:
        node["os"] = os
    props = {}
    if image:
        props["image"] = image
    if services:
        props["services"] = [{"port": p, "proto": "tcp", "name": n} for p, n in services]
    if props:
        node["properties"] = props
    if ifaces:
        node["interfaces"] = [{"name": n, "subnet": s, "ip": ip} for n, s, ip in ifaces]
    return node


def _links(*pairs):
    return [{"key": f"l{i}", "source": a, "target": b} for i, (a, b) in enumerate(pairs, 1)]


# v1.3 training scenarios (beginner -> advanced). Images come from the default allowlist only.
TEMPLATES["small-office"] = {
    "title": "Kantor Kecil (DEMO, pemula)",
    "description": "Satu router, dua PC karyawan, PC admin dan NAS yang tanpa sengaja membuka layanan basis data. Cocok untuk scan pertama.",
    "doc": {
        "zones": [_z("z-inet", "Internet", "internet", "#64748b", -40, 40, 200, 180), _z("z-office", "Kantor", "internal", "#3b82f6", 300, -40, 520, 320)],
        "subnets": [{"key": "s-office", "name": "LAN Kantor", "cidr": "192.168.50.0/24", "gateway": "192.168.50.1", "vlan": 50, "zone": "z-office"}],
        "nodes": [
            _n("inet", "internet", "Internet", "z-inet", 20, 100),
            _n("rtr-1", "firewall", "Router Kantor", None, 200, 100, [("lan0", "s-office", "192.168.50.1")], "rtr-1", "OpenWrt"),
            _n("sw-1", "switch", "Switch", "z-office", 420, 100),
            _n("pc-1", "workstation", "PC Karyawan 1", "z-office", 340, 220, [("eth0", "s-office", "192.168.50.11")], "pc-1", "Windows 11"),
            _n("pc-2", "workstation", "PC Karyawan 2", "z-office", 500, 220, [("eth0", "s-office", "192.168.50.12")], "pc-2", "Windows 11"),
            _n("pc-admin", "server", "PC Admin", "z-office", 660, 220, [("eth0", "s-office", "192.168.50.20")], "pc-admin", "Ubuntu 24.04", "alpine:3.20"),
            _n("nas-1", "server", "NAS / Server File", "z-office", 660, 0, [("eth0", "s-office", "192.168.50.30")], "nas-1", "Linux NAS",
               "redis:7-alpine", [(6379, "redis")]),
        ],
        "links": _links(("inet", "rtr-1"), ("rtr-1", "sw-1"), ("sw-1", "pc-1"), ("sw-1", "pc-2"), ("sw-1", "pc-admin"), ("sw-1", "nas-1")),
    },
}

TEMPLATES["web-3tier"] = {
    "title": "Aplikasi Web 3 Lapis (DEMO, menengah)",
    "description": "Load balancer dan web server di DMZ, server aplikasi, lalu cache Redis tanpa password dan database di zona data.",
    "doc": {
        "zones": [_z("z-inet", "Internet", "internet", "#64748b", -40, 40, 200, 200), _z("z-dmz", "DMZ", "dmz", "#f59e0b", 300, -80, 420, 200),
                  _z("z-app", "Aplikasi", "internal", "#3b82f6", 300, 180, 420, 180), _z("z-data", "Data", "restricted", "#a855f7", 780, 60, 300, 300)],
        "subnets": [{"key": "s-dmz", "name": "DMZ", "cidr": "172.20.10.0/24", "gateway": "172.20.10.1", "vlan": 10, "zone": "z-dmz"},
                    {"key": "s-app", "name": "Aplikasi", "cidr": "10.30.0.0/24", "gateway": "10.30.0.1", "vlan": 20, "zone": "z-app"},
                    {"key": "s-data", "name": "Data", "cidr": "10.40.0.0/24", "gateway": "10.40.0.1", "vlan": 30, "zone": "z-data"}],
        "nodes": [
            _n("inet", "internet", "Internet", "z-inet", 20, 110),
            _n("fw-1", "firewall", "Firewall", None, 220, 110, [("dmz0", "s-dmz", "172.20.10.1"), ("app0", "s-app", "10.30.0.1"), ("data0", "s-data", "10.40.0.1")],
               "fw-1", "pfSense"),
            _n("lb-1", "server", "Load Balancer", "z-dmz", 340, -30, [("eth0", "s-dmz", "172.20.10.5")], "lb-1", "NGINX", "nginx:1.27-alpine", [(80, "http")]),
            _n("web-1", "server", "Web Server", "z-dmz", 540, -30, [("eth0", "s-dmz", "172.20.10.10")], "web-1", "NGINX", "nginx:1.27-alpine", [(80, "http")]),
            _n("app-1", "server", "Server Aplikasi", "z-app", 440, 240, [("eth0", "s-app", "10.30.0.10")], "app-1", "Ubuntu 24.04", "alpine:3.20"),
            _n("cache-1", "database", "Cache Redis", "z-data", 820, 120, [("eth0", "s-data", "10.40.0.20")], "cache-1", "Redis 7", "redis:7-alpine", [(6379, "redis")]),
            _n("db-1", "database", "Database", "z-data", 820, 260, [("eth0", "s-data", "10.40.0.10")], "db-1", "MySQL 8.4", "alpine:3.20", [(3306, "mysql")]),
        ],
        "links": _links(("inet", "fw-1"), ("fw-1", "lb-1"), ("fw-1", "web-1"), ("fw-1", "app-1"), ("fw-1", "cache-1"), ("fw-1", "db-1")),
    },
}

TEMPLATES["soc-enterprise"] = {
    "title": "SOC Enterprise (DEMO, mahir)",
    "description": "Jaringan perusahaan lengkap: DMZ, LAN karyawan, zona server (domain controller simulasi), zona data, dan zona manajemen dengan sensor.",
    "doc": {
        "zones": [_z("z-inet", "Internet", "internet", "#64748b", -60, 60, 200, 200), _z("z-dmz", "DMZ", "dmz", "#f59e0b", 260, -120, 440, 200),
                  _z("z-lan", "LAN Karyawan", "internal", "#3b82f6", 260, 140, 440, 220), _z("z-srv", "Server", "internal", "#22c58b", 760, -120, 300, 200),
                  _z("z-data", "Data", "restricted", "#a855f7", 760, 140, 300, 220), _z("z-mgmt", "Manajemen", "management", "#ef4444", 260, 400, 440, 140)],
        "subnets": [{"key": "s-dmz", "name": "DMZ", "cidr": "172.24.10.0/24", "gateway": "172.24.10.1", "vlan": 10, "zone": "z-dmz"},
                    {"key": "s-lan", "name": "LAN", "cidr": "10.50.0.0/24", "gateway": "10.50.0.1", "vlan": 20, "zone": "z-lan"},
                    {"key": "s-srv", "name": "Server", "cidr": "10.60.0.0/24", "gateway": "10.60.0.1", "vlan": 30, "zone": "z-srv"},
                    {"key": "s-data", "name": "Data", "cidr": "10.70.0.0/24", "gateway": "10.70.0.1", "vlan": 40, "zone": "z-data"},
                    {"key": "s-mgmt", "name": "Manajemen", "cidr": "10.99.0.0/24", "gateway": "10.99.0.1", "vlan": 99, "zone": "z-mgmt"}],
        "nodes": [
            _n("inet", "internet", "Internet", "z-inet", 0, 130),
            _n("fw-core", "firewall", "Core Firewall", None, 160, 130,
               [("dmz0", "s-dmz", "172.24.10.1"), ("lan0", "s-lan", "10.50.0.1"), ("srv0", "s-srv", "10.60.0.1"), ("data0", "s-data", "10.70.0.1"),
                ("mgmt0", "s-mgmt", "10.99.0.1")], "fw-core", "pfSense"),
            _n("web-1", "server", "Web Publik", "z-dmz", 300, -70, [("eth0", "s-dmz", "172.24.10.10")], "web-1", "NGINX", "nginx:1.27-alpine", [(80, "http")]),
            _n("mail-1", "server", "Mail Gateway", "z-dmz", 500, -70, [("eth0", "s-dmz", "172.24.10.20")], "mail-1", "Debian 12", "alpine:3.20", [(25, "smtp")]),
            _n("ws-1", "workstation", "PC Keuangan", "z-lan", 300, 200, [("eth0", "s-lan", "10.50.0.21")], "ws-1", "Windows 11"),
            _n("ws-2", "workstation", "PC HR", "z-lan", 440, 200, [("eth0", "s-lan", "10.50.0.22")], "ws-2", "Windows 11"),
            _n("ws-3", "workstation", "PC IT Helpdesk", "z-lan", 580, 200, [("eth0", "s-lan", "10.50.0.23")], "ws-3", "Windows 11"),
            _n("dc-1", "server", "Domain Controller (simulasi)", "z-srv", 800, -70, [("eth0", "s-srv", "10.60.0.10")], "dc-1", "Windows Server 2022", "alpine:3.20"),
            _n("file-1", "server", "File Server", "z-srv", 940, -70, [("eth0", "s-srv", "10.60.0.20")], "file-1", "Ubuntu 24.04", "nginx:1.27-alpine", [(80, "http")]),
            _n("db-1", "database", "Database Pelanggan", "z-data", 800, 200, [("eth0", "s-data", "10.70.0.10")], "db-1", "MySQL 8.4", "alpine:3.20", [(3306, "mysql")]),
            _n("cache-1", "database", "Cache Sesi", "z-data", 940, 200, [("eth0", "s-data", "10.70.0.20")], "cache-1", "Redis 7", "redis:7-alpine", [(6379, "redis")]),
            _n("siem-1", "sensor", "Kolektor SIEM", "z-mgmt", 320, 450, [("eth0", "s-mgmt", "10.99.0.5")], "siem-1", "Linux"),
            _n("jump-1", "server", "Jump Host Admin", "z-mgmt", 520, 450, [("eth0", "s-mgmt", "10.99.0.10")], "jump-1", "Ubuntu 24.04", "alpine:3.20"),
        ],
        "links": _links(("inet", "fw-core"), ("fw-core", "web-1"), ("fw-core", "mail-1"), ("fw-core", "ws-1"), ("fw-core", "ws-2"), ("fw-core", "ws-3"),
                        ("fw-core", "dc-1"), ("fw-core", "file-1"), ("fw-core", "db-1"), ("fw-core", "cache-1"), ("fw-core", "siem-1"), ("fw-core", "jump-1")),
    },
}


TEMPLATES["ad-office"] = {
    "title": "Kantor dengan Active Directory (realistis)",
    "description": "Kantor yang hidup: domain controller lab.local (Samba AD DC), portal intranet, tiga PC dengan karyawan simulasi "
                   "yang login, membuka file share dan memakai portal, serta satu laptop tamu sebagai titik awal assessment. "
                   "Host agent mengirim log proses, login, file, web dan autentikasi domain (4624/4625) ke SIEM. "
                   "Butuh image lab kantor (dibangun otomatis oleh start.bat/start.sh) dan sekitar 1,5 GB RAM.",
    "doc": {
        "zones": [_z("z-inet", "Internet", "internet", "#64748b", -40, 40, 200, 180), _z("z-srv", "Server", "internal", "#8b5cf6", 300, -200, 560, 200),
                  _z("z-office", "Ruang Kerja", "internal", "#3b82f6", 300, 40, 560, 260)],
        "subnets": [{"key": "s-corp", "name": "LAN Kantor", "cidr": "10.20.10.0/24", "gateway": "10.20.10.1", "vlan": 10, "zone": "z-office"}],
        "nodes": [
            _n("inet", "internet", "Internet", "z-inet", 20, 100),
            _n("fw-1", "firewall", "Firewall Kantor", None, 200, 100, [("lan0", "s-corp", "10.20.10.1")], "fw-1", "OpenWrt"),
            _n("sw-1", "switch", "Switch Inti", "z-office", 420, 100),
            _n("dc01", "server", "Domain Controller (lab.local)", "z-srv", 360, -150, [("eth0", "s-corp", "10.20.10.10")], "dc01",
               "Samba AD DC 4.19", "cyber-range/lab-dc:1.0", [(53, "dns"), (88, "kerberos"), (389, "ldap"), (445, "smb")]),
            _n("portal", "server", "Portal Intranet", "z-srv", 620, -150, [("eth0", "s-corp", "10.20.10.20")], "portal", "Ubuntu 24.04",
               "cyber-range/lab-portal:1.0", [(80, "http")]),
            _n("pc-keu", "workstation", "PC Keuangan", "z-office", 340, 220, [("eth0", "s-corp", "10.20.10.31")], "pc-keu", "Ubuntu 24.04",
               "cyber-range/lab-ws:1.0"),
            _n("pc-pem", "workstation", "PC Pemasaran", "z-office", 500, 220, [("eth0", "s-corp", "10.20.10.32")], "pc-pem", "Ubuntu 24.04",
               "cyber-range/lab-ws:1.0"),
            _n("pc-it", "workstation", "PC IT", "z-office", 660, 220, [("eth0", "s-corp", "10.20.10.33")], "pc-it", "Ubuntu 24.04",
               "cyber-range/lab-ws:1.0"),
            _n("tamu", "workstation", "Laptop Tamu (titik awal assessment)", "z-office", 800, 120, [("eth0", "s-corp", "10.20.10.99")], "laptop-tamu",
               "Ubuntu 24.04", "cyber-range/lab-ws:1.0"),
        ],
        "links": _links(("inet", "fw-1"), ("fw-1", "sw-1"), ("sw-1", "dc01"), ("sw-1", "portal"), ("sw-1", "pc-keu"), ("sw-1", "pc-pem"),
                        ("sw-1", "pc-it"), ("sw-1", "tamu")),
    },
}


def readdress(doc: dict, taken: list) -> tuple[dict, dict]:
    """Copy a template topology, moving every subnet that overlaps `taken` (networks of running labs) to a free range of
    the same size inside 10.64.0.0/10. Gateways and interface IPs keep their host offset, so the lab looks identical apart
    from the addresses. Returns (doc, {old_cidr: new_cidr}). Used when several learners run the same template at once."""
    import copy
    import ipaddress

    doc = copy.deepcopy(doc)
    used = [ipaddress.ip_network(str(t)) for t in taken]
    pool = ipaddress.ip_network("10.64.0.0/10")
    moved, remap = {}, {}
    for s in doc.get("subnets", []):
        net = ipaddress.ip_network(s["cidr"])
        if not any(net.overlaps(u) for u in used):
            used.append(net)
            continue
        new = next((c for c in pool.subnets(new_prefix=max(net.prefixlen, pool.prefixlen)) if not any(c.overlaps(u) for u in used)), None)
        if new is None:
            continue  # nothing free: leave it, the safety check will explain the conflict
        used.append(new)
        moved[s["key"]] = (net, new)
        remap[str(net)] = str(new)
        s["cidr"] = str(new)

    def shift(ip: str, key: str) -> str:
        old, new = moved[key]
        return str(new.network_address + (int(ipaddress.ip_address(ip)) - int(old.network_address)))

    for s in doc.get("subnets", []):
        if s["key"] in moved and s.get("gateway"):
            s["gateway"] = shift(s["gateway"], s["key"])
    for n in doc.get("nodes", []):
        for i in n.get("interfaces") or []:
            if i.get("subnet") in moved and i.get("ip"):
                i["ip"] = shift(i["ip"], i["subnet"])
    return doc, remap
