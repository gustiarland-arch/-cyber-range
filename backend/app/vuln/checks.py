"""Safe, non-destructive vulnerability checks run from a scanner node INSIDE a lab.

The scanner only: opens TCP connections, reads the service banner the server volunteers, sends one Redis `PING`
(a read-only liveness command, used to detect missing authentication) and issues HTTP HEAD/GET requests to a fixed
list of paths, recording status codes and response headers (never response bodies). No exploit, brute force,
credential use or state-changing request exists here. Version-based results are labelled "potential, confirm".
"""
import ipaddress
import re

PROFILES = {
    "quick": [21, 22, 23, 80, 443, 3306, 6379, 8080],
    "standard": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 11211, 27017],
}
BANNER_PORTS = {21, 22, 25, 110, 143, 3306, 5900}
HTTP_PORTS = {80, 8000, 8080}
HTTP_PATHS = ["/", "/.git/HEAD", "/server-status", "/.env", "/phpinfo.php", "/admin/"]
SEC_HEADERS = ("x-frame-options", "x-content-type-options", "content-security-policy")

# Catalogue of builtin entries. `detection`: check = observed behaviour; version = inferred from an advertised version.
BUILTIN = [
    {"code": "CR-VA-001", "title": "Telnet service exposed", "severity": 3, "cvss": 7.5, "cwe": "CWE-319", "category": "cleartext",
     "description": "A Telnet listener accepts connections. Telnet sends credentials and sessions in cleartext.",
     "remediation": "Disable Telnet and use SSH with key-based authentication; restrict management access to an admin segment.",
     "detection": "check"},
    {"code": "CR-VA-002", "title": "FTP service exposed (cleartext)", "severity": 2, "cvss": 5.3, "cwe": "CWE-319", "category": "cleartext",
     "description": "An FTP service is reachable. FTP transmits credentials and data without encryption.",
     "remediation": "Replace FTP with SFTP/FTPS, or restrict it to a trusted segment.", "detection": "check"},
    {"code": "CR-VA-003", "title": "Database port reachable from scanner segment", "severity": 3, "cvss": 7.3, "cwe": "CWE-284", "category": "exposure",
     "description": "A database service port (MySQL, PostgreSQL, MongoDB, Elasticsearch, Memcached, Redis) accepts connections from the scanner's network segment.",
     "remediation": "Bind databases to internal interfaces and allow only application servers through segment firewall rules.", "detection": "check"},
    {"code": "CR-VA-004", "title": "Redis accepts commands without authentication", "severity": 4, "cvss": 9.8, "cwe": "CWE-306", "category": "authentication",
     "description": "The Redis server answered PING with PONG before any AUTH, so any client on the network can read and modify data.",
     "remediation": "Enable `requirepass`/ACLs, keep protected-mode on, and bind Redis to trusted interfaces only.", "detection": "check",
     "references": ["https://redis.io/docs/latest/operate/oss_and_stack/management/security/"]},
    {"code": "CR-VA-005", "title": "Web server discloses its version", "severity": 1, "cvss": 3.7, "cwe": "CWE-200", "category": "information",
     "description": "The HTTP `Server` header advertises product and version, which helps an attacker select known exploits.",
     "remediation": "Suppress version tokens (e.g. nginx `server_tokens off;`, Apache `ServerTokens Prod`).", "detection": "check"},
    {"code": "CR-VA-006", "title": "Missing HTTP security headers", "severity": 1, "cvss": 3.1, "cwe": "CWE-693", "category": "configuration",
     "description": "The web root does not set one or more of X-Frame-Options, X-Content-Type-Options and Content-Security-Policy.",
     "remediation": "Add the missing headers at the web server or application layer.", "detection": "check"},
    {"code": "CR-VA-007", "title": "Git repository metadata exposed over HTTP", "severity": 3, "cvss": 7.5, "cwe": "CWE-538", "category": "exposure",
     "description": "`/.git/HEAD` is served, which usually allows the source tree and its history to be downloaded.",
     "remediation": "Remove the .git directory from the web root or deny access to dot-directories.", "detection": "check"},
    {"code": "CR-VA-008", "title": "Environment file exposed over HTTP", "severity": 4, "cvss": 9.1, "cwe": "CWE-538", "category": "exposure",
     "description": "`/.env` answers with a success status. Such files commonly hold secrets. The scanner records only the status, never the content.",
     "remediation": "Move configuration outside the web root, deny dot-files, and rotate any secret that may have been exposed.", "detection": "check"},
    {"code": "CR-VA-009", "title": "Server status / diagnostic page exposed", "severity": 2, "cvss": 5.3, "cwe": "CWE-200", "category": "exposure",
     "description": "A diagnostic endpoint (`/server-status` or `/phpinfo.php`) is reachable and reveals internal details.",
     "remediation": "Restrict diagnostic endpoints to localhost or an admin network, or disable them.", "detection": "check"},
    {"code": "CR-VA-010", "title": "Administrative web interface reachable", "severity": 2, "cvss": 5.3, "cwe": "CWE-284", "category": "exposure",
     "description": "`/admin/` responds with a non-error status from the scanner segment.",
     "remediation": "Place admin interfaces behind VPN/allowlists and require strong authentication.", "detection": "check"},
    {"code": "CR-VA-011", "title": "Remote desktop / VNC exposed", "severity": 3, "cvss": 7.5, "cwe": "CWE-284", "category": "exposure",
     "description": "An RDP (3389) or VNC (5900) listener is reachable from the scanner segment.",
     "remediation": "Expose remote desktop only via a bastion/VPN with MFA and network-level authentication.", "detection": "check"},
    {"code": "CR-VA-012", "title": "SMB service reachable", "severity": 2, "cvss": 5.9, "cwe": "CWE-284", "category": "exposure",
     "description": "SMB/NetBIOS (139/445) accepts connections from the scanner segment.",
     "remediation": "Block SMB between segments that do not need file sharing; disable SMBv1.", "detection": "check"},
    {"code": "CR-VA-101", "title": "OpenSSH version potentially affected by regreSSHion", "severity": 3, "cvss": 8.1, "cwe": "CWE-364", "category": "outdated",
     "cves": ["CVE-2024-6387"], "detection": "version",
     "description": "The SSH banner advertises an OpenSSH version in the affected ranges (< 4.4p1 or 8.5p1 – 9.7p1) of a signal-handler race "
                    "in sshd on glibc Linux. Distribution backports may already fix it: confirm with the package version.",
     "remediation": "Upgrade OpenSSH to 9.8p1 or later (or the distribution's patched package); as a stop-gap set LoginGraceTime 0.",
     "references": ["https://www.openssh.com/txt/release-9.8"]},
    {"code": "CR-VA-102", "title": "Apache httpd 2.4.49/2.4.50 path traversal", "severity": 4, "cvss": 9.8, "cwe": "CWE-22", "category": "outdated",
     "cves": ["CVE-2021-41773", "CVE-2021-42013"], "detection": "version",
     "description": "The Server header advertises Apache httpd 2.4.49 or 2.4.50, versions with a path traversal (and possible RCE with mod_cgi). Not exploited by the scanner: confirm.",
     "remediation": "Upgrade Apache httpd to 2.4.51 or later.", "references": ["https://httpd.apache.org/security/vulnerabilities_24.html"]},
    {"code": "CR-VA-103", "title": "vsftpd 2.3.4 (backdoored release)", "severity": 4, "cvss": 9.8, "cwe": "CWE-506", "category": "outdated",
     "cves": ["CVE-2011-2523"], "detection": "version",
     "description": "The FTP banner advertises vsftpd 2.3.4; a compromised distribution of this version contained a backdoor. Not triggered by the scanner: confirm.",
     "remediation": "Replace with a current, verified vsftpd build or remove the service."},
]
DB_PORTS = {3306, 5432, 6379, 9200, 11211, 27017}


def _ips(values) -> list[str]:
    return [str(ipaddress.ip_address(v)) for v in values]


def build_script(targets: list[str], ports: list[int]) -> tuple[list[str], int]:
    """One busybox sh script for the whole job. Only canonical IPs and integer ports are interpolated."""
    t = _ips(targets)
    ports = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
    plist = " ".join(map(str, ports))
    banner = " ".join(str(p) for p in sorted(BANNER_PORTS))
    http = " ".join(str(p) for p in sorted(HTTP_PORTS))
    paths = " ".join(HTTP_PATHS)
    script = f"""
for ip in {' '.join(t)}; do
  for p in {plist}; do
    if nc -z -w1 $ip $p 2>/dev/null; then
      echo "open $ip $p"
      case " {banner} " in *" $p "*) b=$( (sleep 2) | nc -w2 $ip $p 2>/dev/null | head -c 256 | tr -cd '[:print:]' ); echo "banner $ip $p $b";; esac
      if [ "$p" = 6379 ]; then r=$(printf 'PING\\r\\n' | nc -w2 $ip 6379 2>/dev/null | head -c 64 | tr -cd '[:print:]'); echo "redis $ip $p $r"; fi
      case " {http} " in *" $p "*)
        for path in {paths}; do
          o=$(wget -S --spider -T 3 -U cyber-range-vuln-scan http://$ip:$p$path 2>&1)
          s=$(echo "$o" | grep -m1 'HTTP/' | awk '{{print $2}}')
          echo "http $ip $p $path ${{s:-none}}"
          if [ "$path" = / ]; then echo "$o" | grep -E '^  [A-Za-z-]+:' | head -40 | while read -r h; do echo "hdr $ip $p $h"; done; fi
        done;;
      esac
    else
      echo "closed $ip $p"
    fi
  done
done
"""
    timeout = min(1800, 20 + len(t) * (len(ports) * 2 + 30))
    return ["sh", "-c", script], timeout


def parse(output: str) -> dict:
    """{ip: {"open": set, "closed": set, "banner": {port: str}, "redis": {port: str}, "http": {port: {path: status}}, "headers": {port: {name: value}}}}"""
    res: dict = {}

    def host(ip):
        return res.setdefault(ip, {"open": set(), "closed": set(), "banner": {}, "redis": {}, "http": {}, "headers": {}})

    for line in output.splitlines():
        parts = line.strip().split(" ", 3)
        try:
            kind, ip, port = parts[0], str(ipaddress.ip_address(parts[1])), int(parts[2])
        except (ValueError, IndexError):
            continue
        rest = parts[3].strip() if len(parts) > 3 else ""
        h = host(ip)
        if kind in ("open", "closed"):
            h[kind].add(port)
        elif kind == "banner":
            h["banner"][port] = rest[:256]
        elif kind == "redis":
            h["redis"][port] = rest[:64]
        elif kind == "http":
            path, _, status = rest.partition(" ")
            h["http"].setdefault(port, {})[path] = int(status) if status.isdigit() else None
        elif kind == "hdr" and ":" in rest:
            name, _, val = rest.partition(":")
            h["headers"].setdefault(port, {})[name.strip().lower()[:64]] = val.strip()[:256]
    return res


def _ver(text: str, rx: str):
    m = re.search(rx, text)
    return m.groups() if m else None


def _openssh_affected(banner: str) -> bool:
    g = _ver(banner, r"OpenSSH_(\d+)\.(\d+)(?:p(\d+))?")
    if not g:
        return False
    v = (int(g[0]), int(g[1]), int(g[2] or 0))
    return v < (4, 4, 1) or (8, 5, 1) <= v <= (9, 7, 1)


def evaluate(host: dict) -> list[dict]:
    """Map observations of one host to catalogue codes. Each result: {code, port, evidence}."""
    out = []
    op = host["open"]

    def add(code, port, **ev):
        out.append({"code": code, "port": port, "evidence": ev})

    if 23 in op:
        add("CR-VA-001", 23, observed="TCP 23 accepted a connection")
    if 21 in op:
        b = host["banner"].get(21, "")
        add("CR-VA-002", 21, observed="TCP 21 accepted a connection", banner=b)
        if re.search(r"vsFTPd 2\.3\.4\b", b, re.I):
            add("CR-VA-103", 21, banner=b, advertised_version="vsftpd 2.3.4", confidence="potential, confirm")
    for p in sorted(op & DB_PORTS):
        add("CR-VA-003", p, observed=f"TCP {p} accepted a connection", banner=host["banner"].get(p, ""))
    for p, r in host["redis"].items():
        if r.startswith("+PONG"):
            add("CR-VA-004", p, observed="PING answered +PONG without AUTH", reply=r)
    for p in sorted(op & {3389, 5900}):
        add("CR-VA-011", p, observed=f"TCP {p} accepted a connection", banner=host["banner"].get(p, ""))
    for p in sorted(op & {139, 445}):
        add("CR-VA-012", p, observed=f"TCP {p} accepted a connection")
    if 22 in op and _openssh_affected(host["banner"].get(22, "")):
        add("CR-VA-101", 22, banner=host["banner"][22], confidence="potential, confirm with package version")
    for p, hdrs in host["headers"].items():
        server = hdrs.get("server", "")
        if re.search(r"/\d", server):
            add("CR-VA-005", p, server=server)
        if re.search(r"Apache/2\.4\.(49|50)\b", server):
            add("CR-VA-102", p, server=server, confidence="potential, confirm")
        if host["http"].get(p, {}).get("/") is not None:
            missing = [h for h in SEC_HEADERS if h not in hdrs]
            if missing:
                add("CR-VA-006", p, missing=missing, status=host["http"][p]["/"])
    for p, paths in host["http"].items():
        ok = {k: v for k, v in paths.items() if v is not None and 200 <= v < 300}
        if "/.git/HEAD" in ok:
            add("CR-VA-007", p, path="/.git/HEAD", status=ok["/.git/HEAD"])
        if "/.env" in ok:
            add("CR-VA-008", p, path="/.env", status=ok["/.env"], note="content not retrieved")
        for d in ("/server-status", "/phpinfo.php"):
            if d in ok:
                add("CR-VA-009", p, path=d, status=ok[d])
        if "/admin/" in paths and paths["/admin/"] is not None and paths["/admin/"] < 400:
            add("CR-VA-010", p, path="/admin/", status=paths["/admin/"])
    return out
