"""Catalogue of the only actions an assessment may run. All are non-destructive inventory and validation steps.

Each action is executed with `docker exec` inside the assessment's attacker container (never on the host), against
addresses that were resolved from the approved lab deployment. Parameters are validated and every value placed in a
command line is a parsed IP address, an integer, or a path matching a strict pattern, so no user text reaches a shell.
There is deliberately no exploitation, credential, persistence, evasion or payload action in this catalogue.
"""
import ipaddress
import itertools
import re

PATH_RX = re.compile(r"^/[A-Za-z0-9._~/-]{0,100}$")
MAX_PORTS = 1024
MAX_HOSTS = 256

ACTIONS = {
    "host_discovery": {
        "title": "Host discovery (ICMP echo)", "mitre": "T1018", "tactic": "Discovery",
        "description": "Ping every address in the in-scope subnets once to inventory live hosts.",
        "params": {},
    },
    "port_scan": {
        "title": "TCP connect port scan", "mitre": "T1046", "tactic": "Discovery",
        "description": "Full TCP handshake to each listed port on every target; no payload is sent.",
        "params": {"ports": "list of ports or ranges, e.g. [22, 80, 443, '8000-8100'] (max 1024)"},
    },
    "http_inventory": {
        "title": "HTTP service inventory", "mitre": "T1595.002", "tactic": "Reconnaissance",
        "description": "HEAD-style requests for a fixed list of paths on each target port; records status and Server header.",
        "params": {"ports": "HTTP ports, e.g. [80]", "paths": "up to 20 paths, e.g. ['/', '/admin', '/robots.txt']"},
    },
    "exposure_check": {
        "title": "Segmentation / exposure check", "mitre": "T1046", "tactic": "Discovery",
        "description": "Verify that sensitive service ports (DB, admin, remote access) are NOT reachable from the attacker's segment. Reachable ones become findings.",
        "params": {"ports": "sensitive ports, default [22, 23, 445, 3306, 3389, 5432, 6379, 27017]"},
    },
    "web_attack_probe": {
        "title": "Web attack-pattern probe (detection test)", "mitre": "T1190", "tactic": "Initial Access",
        "description": "Send a fixed set of harmless GET requests whose query strings contain well-known attack signatures "
                       "(SQL injection, path traversal, script tag) so the SOC can verify web-attack detections. Nothing is exploited: "
                       "the strings are inert test markers and only the response status is recorded.",
        "params": {"ports": "HTTP ports, e.g. [80]"},
    },
    "dns_probe": {
        "title": "Suspicious DNS lookup (detection test)", "mitre": "T1071.004", "tactic": "Command and Control",
        "description": "Send DNS queries for a fixed list of test domains under TLDs often abused by malware (.xyz, .top, .zip) to the first "
                       "target. Labs have no egress, so the lookups stay inside the lab and only produce DNS telemetry.",
        "params": {},
    },
}
SENSITIVE_DEFAULT = [22, 23, 445, 3306, 3389, 5432, 6379, 27017]
# Fixed, inert probe strings: they only need to look like attacks to a detector. Never user-supplied.
WEB_PROBES = ["/?id=1%27%20union%20select%20null--cr-test", "/?file=../../../../etc/passwd&cr-test=1", "/?q=%3Cscript%3Ecr-test%3C/script%3E",
              "/../../etc/passwd", "/search?q=1%20UNION%20SELECT%20version()--cr-test"]
DNS_PROBES = ["cr-detection-test.xyz", "update-check.cr-test.top", "payload.cr-test.zip"]


def expand_ports(spec) -> list[int]:
    if not isinstance(spec, list) or not spec:
        raise ValueError("ports must be a non-empty list")
    out = set()
    for p in spec:
        if isinstance(p, int):
            rng = [p]
        elif isinstance(p, str) and re.fullmatch(r"\d{1,5}-\d{1,5}", p):
            a, b = map(int, p.split("-"))
            if a > b:
                raise ValueError(f"bad range {p}")
            rng = range(a, b + 1)
        elif isinstance(p, str) and p.isdigit():
            rng = [int(p)]
        else:
            raise ValueError(f"bad port {p!r}")
        for x in rng:
            if not 1 <= x <= 65535:
                raise ValueError(f"port {x} out of range")
            out.add(x)
            if len(out) > MAX_PORTS:
                raise ValueError(f"at most {MAX_PORTS} ports per step")
    return sorted(out)


def validate_steps(steps) -> list[str]:
    errs = []
    if not isinstance(steps, list) or not 1 <= len(steps) <= 12:
        return ["a scenario needs 1 to 12 steps"]
    for i, s in enumerate(steps, 1):
        if not isinstance(s, dict) or s.get("action") not in ACTIONS:
            errs.append(f"step {i}: unknown action {s.get('action') if isinstance(s, dict) else s!r}; allowed: {', '.join(ACTIONS)}")
            continue
        p = s.get("params") or {}
        try:
            if s["action"] in ("port_scan", "http_inventory"):
                expand_ports(p.get("ports"))
            if s["action"] == "web_attack_probe" and p.get("ports") is not None:
                expand_ports(p["ports"])
            if s["action"] == "dns_probe" and p:
                raise ValueError("dns_probe takes no parameters")
            if s["action"] == "exposure_check" and p.get("ports") is not None:
                expand_ports(p["ports"])
            if s["action"] == "http_inventory":
                paths = p.get("paths") or ["/"]
                if not isinstance(paths, list) or len(paths) > 20 or not all(isinstance(x, str) and PATH_RX.match(x) for x in paths):
                    raise ValueError("paths must be up to 20 values like /admin (letters, digits, . _ ~ / -)")
        except ValueError as e:
            errs.append(f"step {i}: {e}")
        extra = set(p) - {"ports", "paths"}
        if extra:
            errs.append(f"step {i}: unknown parameters {sorted(extra)}")
    return errs


def _ips(values) -> list[str]:
    return [str(ipaddress.ip_address(v)) for v in values]  # re-parse: only canonical IP text reaches the command


def build_command(action: str, params: dict, targets: list[str], cidrs: list[str]) -> tuple[list[str], int]:
    """Return (argv, timeout_seconds) for busybox sh inside the attacker container."""
    t = _ips(targets)
    if action == "host_discovery":
        hosts = []
        for c in cidrs:
            net = ipaddress.ip_network(c)
            hosts += [str(h) for h in itertools.islice(net.hosts(), MAX_HOSTS)]  # never materialise a large network
        hosts = hosts[:MAX_HOSTS]
        script = "for ip in " + " ".join(hosts) + "; do (ping -c1 -W1 $ip >/dev/null 2>&1 && echo \"up $ip\") & done; wait"
        return ["sh", "-c", script], 30
    if action in ("port_scan", "exposure_check"):
        ports = expand_ports(params.get("ports") or SENSITIVE_DEFAULT)
        plist = " ".join(map(str, ports))
        script = ("for ip in " + " ".join(t) + "; do for p in " + plist +
                  "; do nc -z -w1 $ip $p 2>/dev/null && echo \"open $ip $p\" || echo \"closed $ip $p\"; done; done")
        return ["sh", "-c", script], min(600, 10 + len(t) * len(ports) * 2)
    if action == "http_inventory":
        ports = expand_ports(params.get("ports") or [80])
        paths = [p for p in (params.get("paths") or ["/"]) if PATH_RX.match(p)]
        lines = []
        for ip in t:
            for port in ports:
                for path in paths:
                    lines.append(f"o=$(wget -S --spider -T 3 http://{ip}:{port}{path} 2>&1); "
                                 f"s=$(echo \"$o\" | grep -m1 'HTTP/' | awk '{{print $2}}'); "
                                 f"v=$(echo \"$o\" | grep -i -m1 '^ *Server:' | sed 's/^ *[Ss]erver: *//'); "
                                 f"echo \"http {ip} {port} {path} ${{s:-none}} $v\"")
        return ["sh", "-c", "; ".join(lines)], min(600, 10 + len(lines) * 4)
    if action == "web_attack_probe":
        ports = expand_ports(params.get("ports") or [80])
        lines = []
        for ip in t:
            for port in ports:
                for path in WEB_PROBES:
                    lines.append(f"s=$(wget -S -O /dev/null -T 3 -U cyber-range-detection-test 'http://{ip}:{port}{path}' 2>&1 | grep -m1 'HTTP/' | awk '{{print $2}}'); "
                                 f"echo \"http {ip} {port} {path} ${{s:-none}}\"")
        return ["sh", "-c", "; ".join(lines)], min(600, 10 + len(lines) * 4)
    if action == "dns_probe":
        # ask the first target directly (UDP/53 over the lab bridge) so network sensors see the queries; no answer is expected
        server = t[0] if t else ""
        lines = [f"if nslookup -timeout=2 {d} {server} >/dev/null 2>&1; then echo \"dns {d} resolved\"; else echo \"dns {d} failed\"; fi" for d in DNS_PROBES]
        return ["sh", "-c", "; ".join(lines)], 30
    raise ValueError(f"unknown action {action}")


def parse_output(action: str, output: str) -> dict:
    up, open_, closed, http, dns = [], [], [], [], []
    for line in output.splitlines():
        parts = line.strip().split(" ", 5)
        try:
            if parts[0] == "up" and len(parts) == 2:
                up.append(str(ipaddress.ip_address(parts[1])))
            elif parts[0] in ("open", "closed") and len(parts) == 3:
                (open_ if parts[0] == "open" else closed).append((str(ipaddress.ip_address(parts[1])), int(parts[2])))
            elif parts[0] == "http" and len(parts) >= 5:
                http.append({"ip": str(ipaddress.ip_address(parts[1])), "port": int(parts[2]), "path": parts[3],
                             "status": None if parts[4] == "none" else int(parts[4]) if parts[4].isdigit() else None,
                             "server": (parts[5] if len(parts) > 5 else "").strip()[:128] or None})
            elif parts[0] == "dns" and len(parts) == 3 and parts[1] in DNS_PROBES:
                dns.append({"domain": parts[1], "resolved": parts[2] == "resolved"})
        except (ValueError, IndexError):
            continue
    return {"up": sorted(set(up), key=ipaddress.ip_address), "open": sorted(set(open_)), "closed": sorted(set(closed)), "http": http, "dns": dns}
