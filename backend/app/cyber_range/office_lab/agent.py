"""Host telemetry agent for the office lab (a small Sysmon/auditd stand-in, stdlib only).

Writes normalized JSON events to /var/log/cr/events.jsonl:
  host.process  new process (user, command line, parent)            ~ Sysmon 1 / auditd execve
  host.network  a new listening TCP port                            ~ Sysmon 3 / netstat diff
  host.file     change of a watched system file (hash differs)      ~ FIM / Sysmon 11
  ad.auth       domain controller logon success/failure (4624/4625), from Samba's JSON audit log
  ad.change     directory changes: user created (4720), group membership added (4728/4732/4756)
Secrets never reach the log: command lines are redacted before they are written.
"""
import hashlib
import json
import os
import pwd
import re
import sys
import time

sys.path.insert(0, "/opt/cr")
from common import EVENTS, emit, my_ip  # noqa: E402

ROLE = sys.argv[1] if len(sys.argv) > 1 else "ws"
WATCH = ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers", "/etc/crontab", "/etc/hosts", "/etc/samba/smb.conf",
         "/root/.ssh/authorized_keys", "/home/karyawan/.bashrc"]
SAMBA_LOG = "/var/log/samba/samba.log"
EVENTS_PATH = EVENTS
IGNORE = {"sleep", "runc"}   # runc init: the container runtime itself, before the real command replaces it
REDACT = [(re.compile(r"(Lab|Adm)-[0-9A-Za-z-]{8,}!?"), "[REDACTED]"), (re.compile(r"(-w|--password[= ])\s*\S+"), r"\1 [REDACTED]"),
          (re.compile(r"(-U\s*\S+?)%\S+"), r"\1%[REDACTED]"), (re.compile(r"(--adminpass=)\S+"), r"\1[REDACTED]")]
EVENT_TEXT = {4624: "An account was successfully logged on", 4625: "An account failed to log on",
              4720: "A user account was created", 4728: "A member was added to a security-enabled global group",
              4732: "A member was added to a security-enabled local group", 4756: "A member was added to a security-enabled universal group"}
# Samba reports KDC_ERR_PREAUTH_REQUIRED (the normal first round of every Kerberos logon) as a 4625; Windows does not log it.
BENIGN_STATUS = {"NT_STATUS_PROTOCOL_UNREACHABLE"}
IP = my_ip()
STATE = {"warm": True}   # during start-up the DC's own provisioning (DEMO users, groups) is not reported as changes


def redact(s: str) -> str:
    for rx, rep in REDACT:
        s = rx.sub(rep, s)
    return s


def proc_info(pid: str):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
        if not argv:
            return None
        with open(f"/proc/{pid}/status") as f:
            st = dict(line.split(":", 1) for line in f if ":" in line)
        uid = int(st["Uid"].split()[0])
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = str(uid)
        return {"argv": argv, "user": user, "ppid": st.get("PPid", "").strip()}
    except (OSError, ValueError, KeyError):
        return None


def collector(info: dict) -> bool:
    """The platform reading this agent's own log file (tail/head on events.jsonl), not activity on the host."""
    own = (EVENTS_PATH in a for a in info["argv"])
    if any(own):
        return True
    parent = proc_info(info["ppid"]) if info["ppid"] else None
    return bool(parent) and any(EVENTS_PATH in a for a in parent["argv"])


def comm(pid: str) -> str:
    try:
        return open(f"/proc/{pid}/comm").read().strip()
    except OSError:
        return "?"


def listening() -> set:
    out = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in open(path).readlines()[1:]:
                p = line.split()
                if p[3] == "0A":   # LISTEN
                    out.add(int(p[1].rsplit(":", 1)[1], 16))
        except OSError:
            continue
    return out


def file_hash(path: str):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _addr(v):
    m = re.match(r"ipv[46]:\[?([0-9a-fA-F.:]+?)\]?:(\d+)$", v or "")
    return (m.group(1), int(m.group(2))) if m else (None, None)


def samba_event(r: dict):
    if r.get("type") == "Authentication":
        a = r.get("Authentication", {})
        eid = a.get("eventId")
        if eid not in (4624, 4625):
            return
        if eid == 4625 and a.get("status") in BENIGN_STATUS:
            return      # the client's first AS-REQ without pre-auth data: part of every Kerberos logon, not a failure
        src, _ = _addr(a.get("remoteAddress"))
        _, dport = _addr(a.get("localAddress"))
        user = a.get("clientAccount") or a.get("mappedAccount") or ""
        ok = eid == 4624
        emit(timestamp=r.get("timestamp"), dataset="ad.auth", category="auth", action="logon" if ok else "logon_failed",
             outcome="success" if ok else "failure", severity="info" if ok else "low", src_ip=src, dst_ip=IP, dst_port=dport,
             protocol=(a.get("serviceDescription") or "").lower()[:16], user=user.split("@")[0].lower(),
             signature=f"{eid} {EVENT_TEXT[eid]}", signature_id=str(eid),
             message=f"{EVENT_TEXT[eid]}: {user} via {a.get('serviceDescription')}/{a.get('authDescription')} "
                     f"from {src} ({a.get('status')})")
    elif STATE["warm"]:
        return
    elif r.get("type") == "dsdbChange":
        c = r.get("dsdbChange", {})
        dn = c.get("dn", "")
        attrs = c.get("attributes", {}) or {}
        oc = json.dumps(attrs.get("objectClass", ""))
        if c.get("operation") == "Add" and '"user"' in oc and "CN=Computers" not in dn:
            src, _ = _addr(c.get("remoteAddress"))
            emit(timestamp=r.get("timestamp"), dataset="ad.change", category="auth", action="user_created", outcome="success",
                 severity="low", src_ip=src, dst_ip=IP, user=(c.get("performedBy") or "")[:128] or None,
                 signature=f"4720 {EVENT_TEXT[4720]}", signature_id="4720", message=f"{EVENT_TEXT[4720]}: {dn}")
    elif r.get("type") == "dsdbGroupChange":
        g = r.get("dsdbGroupChange", {})
        if g.get("action") == "Added":
            eid = {"GlobalGroup": 4728, "LocalGroup": 4732, "UniversalGroup": 4756}.get(g.get("groupType", "").split(" ")[0].replace("Security", ""), 4728)
            src, _ = _addr(g.get("remoteAddress"))
            emit(timestamp=r.get("timestamp"), dataset="ad.change", category="auth", action="group_member_added", outcome="success",
                 severity="medium", src_ip=src, dst_ip=IP, signature=f"{eid} {EVENT_TEXT[eid]}", signature_id=str(eid),
                 message=f"{EVENT_TEXT[eid]}: {g.get('user')} -> {g.get('group')}")


def main():
    os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
    seen = set(p for p in os.listdir("/proc") if p.isdigit())
    ports = listening()
    hashes = {p: file_hash(p) for p in WATCH}
    samba_off = 0
    emit(dataset="host.agent", category="host", action="agent_started", outcome="success", src_ip=IP,
         message=f"CYBER RANGE host agent started (role {ROLE})")
    tick = 0
    started = time.time()
    BASELINE = 150      # seconds: the role's own start-up (domain provisioning, services binding) is the baseline, not news
    while True:
        tick += 1
        now = set(p for p in os.listdir("/proc") if p.isdigit())
        for pid in sorted(now - seen, key=int):
            info = proc_info(pid)
            if not info:
                continue
            exe = os.path.basename(info["argv"][0])
            if exe in IGNORE or collector(info):
                continue
            cmd = redact(" ".join(info["argv"]))[:900]
            emit(dataset="host.process", category="host", action="process_start", outcome="success", severity="info", src_ip=IP,
                 user=info["user"], signature=exe[:255], message=f"{cmd} (parent {comm(info['ppid'])})")
        seen = now
        if tick % 20 == 0:
            warm = time.time() - started < BASELINE
            STATE["warm"] = warm
            cur = listening()
            if warm:
                ports |= cur
                hashes = {p: file_hash(p) for p in WATCH}
                cur = ports
            for port in sorted(cur - ports):
                emit(dataset="host.network", category="host", action="listen_new", outcome="success", severity="low",
                     dst_ip=IP, dst_port=port, src_ip=IP, message=f"New listening TCP port {port}")
            ports = cur | ports
            for path in WATCH:
                h = file_hash(path)
                if h != hashes.get(path):
                    if hashes.get(path) is not None or h is not None:
                        emit(dataset="host.file", category="file", action="modified" if h and hashes.get(path) else ("created" if h else "deleted"),
                             outcome="success", severity="medium", src_ip=IP, signature=path, message=f"Watched file changed: {path}")
                    hashes[path] = h
        if ROLE == "dc" and tick % 4 == 0 and os.path.exists(SAMBA_LOG):
            try:
                size = os.path.getsize(SAMBA_LOG)
                if size < samba_off:
                    samba_off = 0
                with open(SAMBA_LOG, "rb") as f:
                    f.seek(samba_off)
                    chunk = f.read(2_000_000)
                end = chunk.rfind(b"\n")
                if end >= 0:
                    for line in chunk[:end].splitlines():
                        line = line.strip()
                        if line.startswith(b"{"):
                            try:
                                samba_event(json.loads(line))
                            except (ValueError, KeyError, TypeError):
                                pass
                    samba_off += end + 1
            except OSError:
                pass
        time.sleep(0.25)   # short-lived commands (kinit, smbclient) last well under a second


if __name__ == "__main__":
    main()
