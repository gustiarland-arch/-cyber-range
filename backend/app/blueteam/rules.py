"""Detection rule language: a list of conditions that must all hold, optionally with a threshold over a time window."""
import ipaddress
import re
from functools import lru_cache

RULE_FIELDS = ("dataset", "category", "action", "outcome", "severity", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
               "host", "user", "signature", "signature_id", "message")
GROUP_FIELDS = ("src_ip", "dst_ip", "user", "host", "signature", "dst_port", "signature_id")
OPS = ("eq", "neq", "in", "not_in", "contains", "startswith", "regex", "gte", "lte", "cidr", "exists")
GROUP_OPS = ("any_of", "none_of")   # value: list of condition lists; any_of = at least one list holds, none_of = no list holds
MAX_DEPTH = 4
NUMERIC = ("severity", "src_port", "dst_port")


@lru_cache(maxsize=512)
def _rx(p: str):
    return re.compile(p, re.IGNORECASE)


@lru_cache(maxsize=512)
def _net(c: str):
    return ipaddress.ip_network(c, strict=False)


def validate_rule(kind: str, conditions: list, threshold: dict | None, group_by: str | None) -> list[str]:
    errs = []
    if kind not in ("match", "threshold"):
        errs.append("kind must be match or threshold")
    if not isinstance(conditions, list) or not conditions:
        errs.append("at least one condition is required")
        conditions = []
    errs += _validate_conditions(conditions, "", 0)
    return errs + _validate_threshold(kind, threshold, group_by)


def _validate_conditions(conditions: list, prefix: str, depth: int) -> list[str]:
    errs = []
    if depth > MAX_DEPTH:
        return [f"condition {prefix or '1'}: nesting is limited to {MAX_DEPTH} levels"]
    for i, c in enumerate(conditions):
        label = f"{prefix}{i + 1}"
        if isinstance(c, dict) and c.get("op") in GROUP_OPS:
            groups = c.get("value")
            if not isinstance(groups, list) or not groups or not all(isinstance(g, list) and g for g in groups):
                errs.append(f"condition {label}: {c['op']} needs a list of non-empty condition lists")
                continue
            for j, g in enumerate(groups):
                errs += _validate_conditions(g, f"{label}.{j + 1}.", depth + 1)
            continue
        errs += [e.replace(f"condition {i + 1}:", f"condition {label}:") for e in _validate_leaf(i, c)]
    return errs


def _validate_leaf(i: int, c) -> list[str]:
    errs = []
    if not isinstance(c, dict):
        errs.append(f"condition {i + 1}: must be an object")
        return errs
    f, op, v = c.get("field"), c.get("op"), c.get("value")
    if f not in RULE_FIELDS:
        errs.append(f"condition {i + 1}: unknown field {f!r}")
    if op not in OPS:
        errs.append(f"condition {i + 1}: unknown operator {op!r}")
        return errs
    if op in ("in", "not_in") and not (isinstance(v, list) and v):
        errs.append(f"condition {i + 1}: {op} needs a non-empty list")
    if op == "regex":
        if not isinstance(v, str) or len(v) > 256:
            errs.append(f"condition {i + 1}: regex must be a string up to 256 chars")
        else:
            try:
                _rx(v)
            except re.error as e:
                errs.append(f"condition {i + 1}: invalid regex ({e})")
    if op == "cidr":
        try:
            _net(str(v))
        except ValueError:
            errs.append(f"condition {i + 1}: invalid CIDR {v!r}")
    if op in ("gte", "lte") and not isinstance(v, int | float):
        errs.append(f"condition {i + 1}: {op} needs a number")
    return errs


def _validate_threshold(kind: str, threshold: dict | None, group_by: str | None) -> list[str]:
    errs = []
    if kind == "threshold":
        t = threshold or {}
        if not isinstance(t.get("count"), int) or not 2 <= t["count"] <= 100000:
            errs.append("threshold.count must be an integer between 2 and 100000")
        if not isinstance(t.get("window_seconds"), int) or not 10 <= t["window_seconds"] <= 86400:
            errs.append("threshold.window_seconds must be between 10 and 86400")
        if t.get("group_by") not in GROUP_FIELDS:
            errs.append(f"threshold.group_by must be one of {', '.join(GROUP_FIELDS)}")
        if t.get("distinct") not in (None, *RULE_FIELDS):
            errs.append("threshold.distinct must be an event field")
    if group_by not in (None, "", *GROUP_FIELDS):
        errs.append(f"group_by must be one of {', '.join(GROUP_FIELDS)}")
    return errs


def _cmp(op, actual, expected) -> bool:
    if op == "exists":
        return (actual is not None and actual != "") == bool(expected if expected is not None else True)
    if actual is None:
        return op in ("neq", "not_in")
    if op == "eq":
        return str(actual).lower() == str(expected).lower()
    if op == "neq":
        return str(actual).lower() != str(expected).lower()
    if op == "in":
        return str(actual).lower() in {str(x).lower() for x in expected}
    if op == "not_in":
        return str(actual).lower() not in {str(x).lower() for x in expected}
    if op == "contains":
        return str(expected).lower() in str(actual).lower()
    if op == "startswith":
        return str(actual).lower().startswith(str(expected).lower())
    if op == "regex":
        return bool(_rx(expected).search(str(actual)))
    if op in ("gte", "lte"):
        try:
            a = float(actual)
        except (TypeError, ValueError):
            return False
        return a >= expected if op == "gte" else a <= expected
    if op == "cidr":
        try:
            return ipaddress.ip_address(str(actual)) in _net(str(expected))
        except ValueError:
            return False
    return False


def _holds(c: dict, ev: dict) -> bool:
    if c["op"] == "any_of":
        return any(matches(g, ev) for g in c["value"])
    if c["op"] == "none_of":
        return not any(matches(g, ev) for g in c["value"])
    return _cmp(c["op"], ev.get(c["field"]), c.get("value"))


def matches(conditions: list, ev: dict) -> bool:
    return all(_holds(c, ev) for c in conditions)


# Failed domain logons: 4625 (Samba DC in the app's office lab, Windows NTLM/interactive), 4771 Kerberos pre-authentication
# failed and 4768 TGT request failed (Windows DC in a Lab Kit). 4776 is left out: Windows logs it next to 4625 for the
# same NTLM attempt, so counting both would double every failure.
AD_FAILED_LOGON = [{"field": "dataset", "op": "eq", "value": "ad.auth"}, {"field": "outcome", "op": "eq", "value": "failure"},
                   {"field": "signature_id", "op": "in", "value": ["4625", "4771", "4768"]}]
# CR-AD-001/002 as shipped in local-1.3.0; upgraded in place by seed() when an operator has not edited them
AD_FAILED_LOGON_V13 = [{"field": "dataset", "op": "eq", "value": "ad.auth"}, {"field": "signature_id", "op": "eq", "value": "4625"}]

BUILTIN_RULES = [
    {"code": "CR-TI-001", "name": "Threat intelligence indicator match", "severity": 2, "kind": "intel", "group_by": "indicator",
     "description": "Event berisi indikator aktif (IP, CIDR, domain, URL, hash, email) dengan confidence 30 atau lebih. "
                    "Severity alert dinaikkan ke severity indikator. Dikelola di Threat Intelligence.",
     "conditions": [], "mitre_tactic": "Command and Control", "mitre_technique": "T1071"},
    {"code": "CR-AUTH-001", "name": "SSH brute force", "severity": 3, "kind": "threshold",
     "description": "Lima kali atau lebih login SSH gagal dari satu sumber dalam 60 detik.",
     "conditions": [{"field": "category", "op": "eq", "value": "auth"}, {"field": "outcome", "op": "eq", "value": "failure"},
                    {"field": "protocol", "op": "eq", "value": "ssh"}],
     "threshold": {"count": 5, "window_seconds": 60, "group_by": "src_ip"}, "mitre_tactic": "Credential Access", "mitre_technique": "T1110.001"},
    {"code": "CR-AUTH-002", "name": "Refused local sessions", "severity": 3, "kind": "threshold",
     "description": "Lima kali atau lebih permintaan sesi CYBER RANGE ditolak dari satu alamat dalam 5 menit (akses dari luar komputer ini, situs lain, atau DNS rebinding).",
     "conditions": [{"field": "dataset", "op": "eq", "value": "platform.auth"}, {"field": "outcome", "op": "eq", "value": "failure"}],
     "threshold": {"count": 5, "window_seconds": 300, "group_by": "src_ip"}, "mitre_tactic": "Credential Access", "mitre_technique": "T1110"},
    {"code": "CR-AUTH-003", "name": "Repeated access denied", "severity": 2, "kind": "threshold",
     "description": "Satu akun platform ditolak izinnya sepuluh kali atau lebih dalam 5 menit (percobaan mencari hak akses).",
     "conditions": [{"field": "dataset", "op": "eq", "value": "platform.authz"}],
     "threshold": {"count": 10, "window_seconds": 300, "group_by": "user"}, "mitre_tactic": "Discovery", "mitre_technique": "T1069"},
    {"code": "CR-NET-001", "name": "Port scan", "severity": 2, "kind": "threshold",
     "description": "Satu sumber menghubungi 20 atau lebih port tujuan berbeda dalam 60 detik.",
     "conditions": [{"field": "category", "op": "in", "value": ["network", "ids"]}, {"field": "dst_port", "op": "exists", "value": True}],
     "threshold": {"count": 20, "window_seconds": 60, "group_by": "src_ip", "distinct": "dst_port"}, "mitre_tactic": "Discovery", "mitre_technique": "T1046"},
    {"code": "CR-IDS-001", "name": "High severity IDS alert", "severity": 3, "kind": "match", "group_by": "signature",
     "description": "Event Suricata, notice Zeek atau event Wazuh dengan severity high atau critical.",
     "conditions": [{"field": "category", "op": "eq", "value": "ids"}, {"field": "severity", "op": "gte", "value": 3}],
     "mitre_tactic": "Initial Access", "mitre_technique": "T1190"},
    {"code": "CR-HOST-001", "name": "Privilege escalation via sudo failure", "severity": 2, "kind": "threshold",
     "description": "Tiga kali percobaan sudo/su gagal oleh satu pengguna dalam 2 menit.",
     "conditions": [{"field": "action", "op": "in", "value": ["sudo", "su"]}, {"field": "outcome", "op": "eq", "value": "failure"}],
     "threshold": {"count": 3, "window_seconds": 120, "group_by": "user"}, "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.003"},
    {"code": "CR-WEB-001", "name": "Web attack pattern in HTTP request", "severity": 3, "kind": "match", "group_by": "src_ip",
     "description": "Permintaan HTTP berisi pola umum SQL injection, path traversal atau command injection.",
     "conditions": [{"field": "category", "op": "eq", "value": "http"},
                    {"field": "message", "op": "regex", "value": r"(union(\s|%20|\+)+select|\.\./\.\./|/etc/passwd|<script|;\s*(cat|wget|curl)\s)"}],
     "mitre_tactic": "Initial Access", "mitre_technique": "T1190"},
    # 1.8.0: early-stage reconnaissance. Written on fields that Zeek conn/http, Suricata flow/http and the platform's
    # red team activity record all produce, so the same rule fires on sensor evidence and on the activity record.
    {"code": "CR-NET-002", "name": "Host sweep (ICMP to many addresses)", "severity": 2, "kind": "threshold",
     "description": "Satu sumber mengirim ICMP echo ke empat alamat berbeda atau lebih dalam 60 detik (pemetaan host hidup). "
                    "Pemantauan jaringan yang sah biasanya berasal dari server monitoring yang sudah dikenal.",
     "conditions": [{"field": "category", "op": "eq", "value": "network"},
                    {"op": "any_of", "value": [[{"field": "protocol", "op": "eq", "value": "icmp"}],
                                               [{"field": "action", "op": "eq", "value": "icmp_echo"}]]}],
     "threshold": {"count": 4, "window_seconds": 60, "group_by": "src_ip", "distinct": "dst_ip"},
     "mitre_tactic": "Discovery", "mitre_technique": "T1018"},
    {"code": "CR-NET-003", "name": "Targeted service port scan", "severity": 2, "kind": "threshold",
     "description": "Satu sumber mencoba delapan port tujuan berbeda atau lebih dalam 2 menit. Melengkapi CR-NET-001 (20 port/60 detik) "
                    "untuk pemindaian terarah ke port layanan umum, yang lebih pelan dan lebih sering dipakai penyerang sungguhan.",
     "conditions": [{"field": "category", "op": "eq", "value": "network"}, {"field": "dst_port", "op": "exists", "value": True},
                    {"field": "protocol", "op": "neq", "value": "icmp"}],
     "threshold": {"count": 8, "window_seconds": 120, "group_by": "src_ip", "distinct": "dst_port"},
     "mitre_tactic": "Discovery", "mitre_technique": "T1046"},
    {"code": "CR-WEB-003", "name": "HTTP path enumeration", "severity": 2, "kind": "threshold",
     "description": "Satu sumber meminta sepuluh URL berbeda atau lebih dalam 2 menit yang tidak berhasil (bukan 200/206/304), "
                    "pola pemindai direktori atau inventaris layanan web. Halaman yang berhasil dimuat tidak dihitung, jadi browsing biasa tidak memicu.",
     "conditions": [{"field": "category", "op": "eq", "value": "http"},
                    {"field": "outcome", "op": "not_in", "value": ["200", "206", "304"]}],
     "threshold": {"count": 10, "window_seconds": 120, "group_by": "src_ip", "distinct": "message"},
     "mitre_tactic": "Reconnaissance", "mitre_technique": "T1595.002"},
    {"code": "CR-DNS-001", "name": "DNS query to suspicious TLD", "severity": 1, "kind": "match", "group_by": "host",
     "description": "Lookup DNS ke domain dengan TLD yang sering disalahgunakan untuk infrastruktur malware.",
     "conditions": [{"field": "category", "op": "eq", "value": "dns"}, {"field": "host", "op": "regex", "value": r"\.(zip|mov|top|xyz|tk|gq|cf|ml)\.?$"}],
     "mitre_tactic": "Command and Control", "mitre_technique": "T1071.004"},
    # ---- office lab (Active Directory domain controller, intranet portal, host agents)
    {"code": "CR-AD-001", "name": "Many failed domain logons from one source", "severity": 3, "kind": "threshold",
     "description": "Sepuluh atau lebih logon domain gagal (4625, atau 4771/4768 Kerberos di DC Windows) dari satu alamat dalam 2 menit. Karyawan yang salah ketik "
                    "biasanya gagal sekali atau dua kali; lonjakan seperti ini menandakan tebak-tebakan password.",
     "conditions": AD_FAILED_LOGON,
     "threshold": {"count": 10, "window_seconds": 120, "group_by": "src_ip"}, "mitre_tactic": "Credential Access", "mitre_technique": "T1110"},
    {"code": "CR-AD-002", "name": "Failed logons against many domain accounts", "severity": 3, "kind": "threshold",
     "description": "Logon domain gagal untuk lima akun berbeda atau lebih dari satu alamat dalam 5 menit (pola password spraying).",
     "conditions": AD_FAILED_LOGON,
     "threshold": {"count": 5, "window_seconds": 300, "group_by": "src_ip", "distinct": "user"}, "mitre_tactic": "Credential Access",
     "mitre_technique": "T1110.003"},
    {"code": "CR-AD-003", "name": "Domain user account created", "severity": 2, "kind": "match", "group_by": "host",
     "description": "Akun pengguna baru dibuat di domain (event 4720). Pastikan pembuatannya sesuai permintaan resmi.",
     "conditions": [{"field": "dataset", "op": "eq", "value": "ad.change"}, {"field": "signature_id", "op": "eq", "value": "4720"}],
     "mitre_tactic": "Persistence", "mitre_technique": "T1136.002"},
    {"code": "CR-AD-004", "name": "Member added to a privileged domain group", "severity": 4, "kind": "match", "group_by": "host",
     "description": "Akun ditambahkan ke grup istimewa (Domain Admins, Enterprise Admins, Schema Admins, Administrators).",
     "conditions": [{"field": "dataset", "op": "eq", "value": "ad.change"}, {"field": "signature_id", "op": "in", "value": ["4728", "4732", "4756"]},
                    {"field": "message", "op": "regex", "value": r"(Domain Admins|Enterprise Admins|Schema Admins|Administrators)"}],
     "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1098"},
    {"code": "CR-HOST-002", "name": "Reconnaissance tool started on a host", "severity": 2, "kind": "match", "group_by": "host",
     "description": "Host agent melihat alat pemindai atau enumerasi dijalankan (nmap, masscan, nikto, enum4linux, ldapsearch, rpcclient, "
                    "atau loop nc -z). Di workstation karyawan, ini hampir tidak pernah normal.",
     "conditions": [{"field": "dataset", "op": "eq", "value": "host.process"},
                    {"field": "message", "op": "regex", "value": r"(\b(nmap|masscan|nikto|enum4linux|ldapsearch|rpcclient)\b|nc -z)"}],
     "mitre_tactic": "Discovery", "mitre_technique": "T1046"},
    {"code": "CR-HOST-003", "name": "Watched system file changed", "severity": 3, "kind": "match", "group_by": "host",
     "description": "File sistem yang diawasi berubah (/etc/passwd, /etc/shadow, /etc/sudoers, crontab, authorized_keys, smb.conf).",
     "conditions": [{"field": "dataset", "op": "eq", "value": "host.file"}], "mitre_tactic": "Persistence", "mitre_technique": "T1098.004"},
    {"code": "CR-HOST-004", "name": "New listening port on a host", "severity": 1, "kind": "match", "group_by": "host",
     "description": "Host mulai mendengarkan di port TCP baru setelah agent berjalan. Bisa layanan sah yang baru dipasang, bisa juga backdoor.",
     "conditions": [{"field": "dataset", "op": "eq", "value": "host.network"}, {"field": "action", "op": "eq", "value": "listen_new"}],
     "mitre_tactic": "Command and Control", "mitre_technique": "T1571"},
    {"code": "CR-WEB-002", "name": "Repeated portal sign-in failures", "severity": 2, "kind": "threshold",
     "description": "Lima kali atau lebih login portal intranet gagal dari satu alamat dalam 5 menit.",
     "conditions": [{"field": "dataset", "op": "eq", "value": "web.auth"}, {"field": "outcome", "op": "eq", "value": "failure"}],
     "threshold": {"count": 5, "window_seconds": 300, "group_by": "src_ip"}, "mitre_tactic": "Credential Access", "mitre_technique": "T1110"},
    {"code": "CR-LAB-001", "name": "Lab kill switch engaged", "severity": 4, "kind": "match",
     "description": "Seseorang mengaktifkan kill switch lab global.",
     "conditions": [{"field": "dataset", "op": "eq", "value": "platform.lab"}, {"field": "action", "op": "eq", "value": "lab.killswitch"},
                    {"field": "signature", "op": "eq", "value": "engaged"}],
     "mitre_tactic": "Impact", "mitre_technique": "T1489"},
]
