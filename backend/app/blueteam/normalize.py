"""Parsers that turn sensor records into the normalized SecurityEvent shape.

Supported inputs:
- zeek:     Zeek JSON logs (conn, dns, http, ssh, notice, ssl, files, weird; nested or dotted id fields)
- suricata: Suricata EVE JSON (alert, flow, dns, http, tls, ssh, anomaly, fileinfo, drop)
- wazuh:    Wazuh alerts.json
- syslog:   RFC 3164 / RFC 5424 lines (sshd/sudo/su authentication messages are recognised)
- json:     already-normalized records using the field names of SecurityEvent
"""
import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta

from app.core.database import utcnow

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FIELDS = ("dataset", "category", "action", "outcome", "severity", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
          "host", "user", "signature", "signature_id", "message")


class NormalizeError(ValueError):
    pass


class Skip(Exception):  # noqa: N818 - control flow: record intentionally not stored (e.g. Suricata stats)
    pass


def uid_for(raw) -> str:
    if isinstance(raw, dict) and isinstance(raw.get("event_uid"), str) and 0 < len(raw["event_uid"]) <= 64:
        return raw["event_uid"]
    canon = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str) if not isinstance(raw, str) else raw
    return hashlib.sha256(canon.encode()).hexdigest()


def parse_time(v) -> datetime:
    if v is None or v == "":
        raise NormalizeError("missing timestamp")
    if isinstance(v, int | float) or (isinstance(v, str) and re.fullmatch(r"\d{9,11}(\.\d+)?", v)):
        dt = datetime.fromtimestamp(float(v), UTC)
    elif isinstance(v, str):
        s = v.strip().replace("Z", "+00:00")
        s = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", s)  # +0000 -> +00:00 (Suricata, Wazuh)
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            raise NormalizeError(f"unparseable timestamp {v!r}") from None
        dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    else:
        raise NormalizeError("invalid timestamp type")
    naive = dt.replace(tzinfo=None)
    if naive > utcnow() + timedelta(minutes=5):
        raise NormalizeError("timestamp is in the future")
    return naive


def _ip(v):
    if v in (None, "", "-"):
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def _port(v):
    try:
        p = int(v)
        return p if 0 <= p <= 65535 else None
    except (TypeError, ValueError):
        return None


def _s(v, n):
    if v in (None, "", "-"):
        return None
    return str(v)[:n]


def _finish(raw_ts, ev: dict) -> dict:
    ev["occurred_at"] = parse_time(raw_ts)
    ev["severity"] = max(0, min(4, int(ev.get("severity") or 0)))
    for k in ("src_ip", "dst_ip"):
        ev[k] = _ip(ev.get(k))
    for k in ("src_port", "dst_port"):
        ev[k] = _port(ev.get(k))
    for k, n in (("dataset", 32), ("category", 16), ("action", 64), ("outcome", 16), ("protocol", 16), ("host", 255),
                 ("user", 128), ("signature", 255), ("signature_id", 32)):
        ev[k] = _s(ev.get(k), n)
    ev["message"] = (ev.get("message") or ev.get("signature") or ev["dataset"] or "")[:1024]
    if not ev.get("category"):
        ev["category"] = "other"
    return ev


# ------------------------------------------------------------------ Zeek
def _zget(r, a, b):
    if a in r:
        return r[a]
    cur = r
    for part in a.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return r.get(b)
        cur = cur[part]
    return cur


def zeek(r: dict, path: str | None = None) -> dict:
    if not isinstance(r, dict):
        raise NormalizeError("zeek record must be a JSON object")
    p = r.get("_path") or path
    if not p:
        raise NormalizeError("zeek record needs _path (or pass dataset=zeek.<log>)")
    ev = {"dataset": f"zeek.{p}", "src_ip": _zget(r, "id.orig_h", "src"), "src_port": _zget(r, "id.orig_p", "p"),
          "dst_ip": _zget(r, "id.resp_h", "dst"), "dst_port": _zget(r, "id.resp_p", "dst_p"), "protocol": r.get("proto"), "category": "network"}
    if p == "conn":
        st = r.get("conn_state")
        ev.update(action=st, outcome="failure" if st in ("REJ", "S0", "RSTO", "RSTOS0", "RSTR", "SH") else "success",
                  message=f"conn {ev['src_ip']}:{ev['src_port']} -> {ev['dst_ip']}:{ev['dst_port']}/{r.get('proto')} {st or ''} {r.get('service') or ''}".strip())
        ev["protocol"] = r.get("service") or r.get("proto")
    elif p == "dns":
        ev.update(category="dns", action=r.get("rcode_name"), host=r.get("query"), protocol="dns",
                  message=f"dns {r.get('qtype_name') or ''} {r.get('query')} -> {r.get('rcode_name') or ''} {','.join(map(str, r.get('answers') or []))}".strip())
    elif p == "http":
        ev.update(category="http", action=r.get("method"), host=r.get("host"), protocol="http", outcome=str(r.get("status_code") or ""),
                  message=f"{r.get('method')} {r.get('host') or ''}{r.get('uri') or ''} {r.get('status_code') or ''} ua={r.get('user_agent') or '-'}")
    elif p == "ssh":
        ok = r.get("auth_success")
        ev.update(category="auth", protocol="ssh", action="login", outcome="success" if ok else "failure" if ok is False else None,
                  message=f"ssh auth {'success' if ok else 'failure' if ok is False else 'unknown'} attempts={r.get('auth_attempts')} client={r.get('client') or '-'}")
    elif p == "notice":
        ev.update(category="ids", severity=2, signature=r.get("note"), action="notice", message=r.get("msg") or r.get("note"))
    elif p == "ssl":
        ev.update(category="network", protocol="tls", host=r.get("server_name"), action=r.get("version"),
                  message=f"tls {r.get('version') or ''} sni={r.get('server_name') or '-'} established={r.get('established')}")
    elif p == "files":
        ev.update(category="file", action=r.get("mime_type"), signature=r.get("sha256") or r.get("md5"),
                  message=f"file {r.get('filename') or r.get('fuid')} {r.get('mime_type') or ''} sha256={r.get('sha256') or '-'}")
    elif p == "weird":
        ev.update(category="network", severity=1, signature=r.get("name"), action="weird", message=f"weird {r.get('name')} {r.get('addl') or ''}")
    else:
        ev["message"] = f"zeek {p}"
    return _finish(r.get("ts"), ev)


# ------------------------------------------------------------------ Suricata EVE
_SURI_SEV = {1: 3, 2: 2, 3: 1}


def suricata(r: dict) -> dict:
    if not isinstance(r, dict):
        raise NormalizeError("EVE record must be a JSON object")
    et = r.get("event_type")
    if et in ("stats", None):
        raise Skip()
    ev = {"dataset": f"suricata.{et}", "src_ip": r.get("src_ip"), "src_port": r.get("src_port"), "dst_ip": r.get("dest_ip"),
          "dst_port": r.get("dest_port"), "protocol": r.get("app_proto") or r.get("proto"), "host": r.get("host"), "category": "network"}
    if et in ("alert", "drop"):
        a = r.get("alert") or {}
        act = a.get("action") or ("blocked" if et == "drop" else "allowed")
        ev.update(category="ids", severity=_SURI_SEV.get(a.get("severity"), 1), signature=a.get("signature"),
                  signature_id=a.get("signature_id"), action=act,
                  message=f"[{a.get('category') or 'alert'}] {a.get('signature')} ({act})")
    elif et == "dns":
        d = r.get("dns") or {}
        q = d.get("rrname") or ((d.get("queries") or [{}])[0].get("rrname"))
        ev.update(category="dns", host=q, action=d.get("rcode") or d.get("type"), message=f"dns {d.get('type') or ''} {q} {d.get('rcode') or ''}".strip())
    elif et == "http":
        h = r.get("http") or {}
        ev.update(category="http", host=h.get("hostname"), action=h.get("http_method"), outcome=str(h.get("status") or ""),
                  message=f"{h.get('http_method')} {h.get('hostname') or ''}{h.get('url') or ''} {h.get('status') or ''} ua={h.get('http_user_agent') or '-'}")
    elif et == "tls":
        t = r.get("tls") or {}
        ev.update(host=t.get("sni"), action=t.get("version"), message=f"tls {t.get('version') or ''} sni={t.get('sni') or '-'}")
    elif et == "ssh":
        s = r.get("ssh") or {}
        ev.update(category="auth", protocol="ssh", message=f"ssh client={(s.get('client') or {}).get('software_version')} server={(s.get('server') or {}).get('software_version')}")
    elif et == "flow":
        f = r.get("flow") or {}
        ev.update(action=f.get("state"), message=f"flow {ev['src_ip']}:{ev['src_port']} -> {ev['dst_ip']}:{ev['dst_port']} {f.get('state') or ''} {f.get('reason') or ''}".strip())
    elif et == "anomaly":
        an = r.get("anomaly") or {}
        ev.update(severity=1, signature=an.get("event"), action="anomaly", message=f"anomaly {an.get('type')} {an.get('event')}")
    elif et == "fileinfo":
        fi = r.get("fileinfo") or {}
        ev.update(category="file", signature=fi.get("sha256"), message=f"file {fi.get('filename')} {fi.get('magic') or ''}")
    else:
        ev["message"] = f"suricata {et}"
    return _finish(r.get("timestamp"), ev)


# ------------------------------------------------------------------ Wazuh
def _wazuh_sev(level) -> int:
    lv = int(level or 0)
    return 0 if lv <= 3 else 1 if lv <= 6 else 2 if lv <= 9 else 3 if lv <= 12 else 4


def wazuh(r: dict) -> dict:
    if not isinstance(r, dict) or not isinstance(r.get("rule"), dict):
        raise NormalizeError("Wazuh alert must be a JSON object with a rule")
    rule, agent, data = r["rule"], r.get("agent") or {}, r.get("data") or {}
    groups = [g.lower() for g in rule.get("groups") or []]
    cat = "auth" if {"authentication_failed", "authentication_success", "sshd", "pam", "sudo"} & set(groups) else \
        "ids" if {"ids", "suricata", "attack", "web"} & set(groups) else "host"
    outcome = "failure" if "authentication_failed" in groups or "authentication_failures" in groups else \
        "success" if "authentication_success" in groups else None
    action = "sudo" if "sudo" in groups else "su" if "su" in groups else (",".join(groups[:3]) or None)
    if action in ("sudo", "su") and outcome is None:
        outcome = "failure" if re.search(r"incorrect password|authentication failure|FAILED", str(r.get("full_log") or "") + str(rule.get("description")), re.I) else "success"
    ev = {"dataset": "wazuh.alert", "category": cat, "severity": _wazuh_sev(rule.get("level")), "signature": rule.get("description"),
          "signature_id": rule.get("id"), "action": action, "outcome": outcome,
          "host": agent.get("name"), "src_ip": data.get("srcip"), "src_port": data.get("srcport"), "dst_ip": data.get("dstip") or agent.get("ip"),
          "dst_port": data.get("dstport"), "user": data.get("dstuser") or data.get("srcuser"),
          "message": f"{rule.get('description')} · {(r.get('full_log') or '')[:600]}"}
    return _finish(r.get("timestamp"), ev)


# ------------------------------------------------------------------ syslog
_R5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[.*?\]) ?(.*)$")
_R3164 = re.compile(r"^<(\d{1,3})>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^:\[]+)(?:\[(\d+)\])?: ?(.*)$")
_SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_SSH_OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)")
_SSH_INVALID = re.compile(r"Invalid user (\S+) from (\S+)(?: port (\d+))?")
_SUDO = re.compile(r"^\s*(\S+) : .*COMMAND=(.*)$")
_SYSLOG_SEV = {0: 4, 1: 4, 2: 4, 3: 3, 4: 2, 5: 1, 6: 0, 7: 0}


def syslog(line: str, now: datetime | None = None) -> dict:
    if not isinstance(line, str):
        raise NormalizeError("syslog record must be a string")
    line = line.strip()
    m = _R5424.match(line)
    if m:
        pri, ts, host, app, _proc, _msgid, msg = m.groups()
    else:
        m = _R3164.match(line)
        if not m:
            raise NormalizeError("not an RFC 3164/5424 syslog line")
        pri, ts3164, host, app, _proc, msg = m.groups()
        now = now or utcnow()
        dt = datetime.strptime(f"{now.year} {ts3164}", "%Y %b %d %H:%M:%S")
        if dt > now + timedelta(days=1):  # December logs read in January
            dt = dt.replace(year=now.year - 1)
        ts = dt.isoformat()
    pri = int(pri)
    ev = {"dataset": f"syslog.{app.strip()[:24]}", "category": "host", "severity": _SYSLOG_SEV.get(pri & 7, 0), "host": host,
          "protocol": None, "message": msg}
    app = app.strip()
    if app.startswith("sshd"):
        for rx, outcome in ((_SSH_FAIL, "failure"), (_SSH_INVALID, "failure"), (_SSH_OK, "success")):
            mm = rx.search(msg)
            if mm:
                ev.update(category="auth", action="login", outcome=outcome, user=mm.group(1), src_ip=mm.group(2),
                          src_port=mm.group(3) if mm.lastindex >= 3 else None, protocol="ssh", severity=1 if outcome == "failure" else 0)
                break
    elif app in ("sudo", "su"):
        mm = _SUDO.match(msg)
        ev.update(category="auth", action=app, user=mm.group(1) if mm else None, outcome="failure" if "incorrect password" in msg or "FAILED" in msg or "failed" in msg else "success")
    return _finish(ts, ev)


# ------------------------------------------------------------------ generic normalized JSON
def generic(r: dict) -> dict:
    if not isinstance(r, dict):
        raise NormalizeError("record must be a JSON object")
    ev = {k: r.get(k) for k in FIELDS}
    sev = r.get("severity")
    ev["severity"] = SEV.get(sev, 0) if isinstance(sev, str) else sev
    ev["dataset"] = ev["dataset"] or "json.generic"
    if ev.get("category") and ev["category"] not in ("network", "ids", "auth", "host", "dns", "http", "file", "platform", "other"):
        raise NormalizeError(f"unknown category {ev['category']!r}")
    return _finish(r.get("timestamp") or r.get("@timestamp") or r.get("occurred_at"), ev)


PARSERS = {"zeek": zeek, "suricata": suricata, "wazuh": wazuh, "syslog": syslog, "json": generic}


def normalize(kind: str, record) -> dict:
    if kind not in PARSERS:
        raise NormalizeError(f"no parser for {kind}")
    return PARSERS[kind](record)


def split_lines(kind: str, text: str) -> list:
    """File upload helper: NDJSON for JSON formats, one line per record for syslog."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):  # Zeek TSV headers / comments
            continue
        if kind == "syslog":
            out.append(line)
        else:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"__invalid_line__": i})
    return out
