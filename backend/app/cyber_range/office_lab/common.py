"""Shared helpers for the office lab roles (stdlib only).

Lab environment (set by the CYBER RANGE lab worker, never shown to users):
  CR_LAB_SEED   per-lab random secret; DEMO account passwords are derived from it, so they differ in every lab and are
                never stored or displayed anywhere
  CR_DOMAIN     DNS domain of the lab (default lab.local)
  CR_PEERS      role=ip pairs of the other office nodes, e.g. "dc=10.20.10.10,portal=10.20.10.20"
  CR_NODE       node key of this container
  CR_EVENTS     telemetry file (default /var/log/cr/events.jsonl; Lab Kit VMs write to the shared telemetry folder)
  CR_DC_HOST    name of the domain controller for Kerberos file share access (Lab Kit with a Windows DC: dc01)
"""
import hashlib
import json
import os
import socket
import time

EVENTS = os.environ.get("CR_EVENTS") or "/var/log/cr/events.jsonl"
DOMAIN = os.environ.get("CR_DOMAIN", "lab.local").lower()
REALM = DOMAIN.upper()
NETBIOS = DOMAIN.split(".")[0].upper()[:15]
NODE = os.environ.get("CR_NODE") or socket.gethostname()

# DEMO employees of the simulated company. Department decides the file shares they use.
EMPLOYEES = [
    ("budi.santoso", "Budi Santoso", "Keuangan"),
    ("siti.rahma", "Siti Rahma", "Keuangan"),
    ("agus.pratama", "Agus Pratama", "Pemasaran"),
    ("dewi.lestari", "Dewi Lestari", "Pemasaran"),
    ("rina.wijaya", "Rina Wijaya", "SDM"),
    ("andi.saputra", "Andi Saputra", "IT"),
]
GROUPS = ["Keuangan", "Pemasaran", "SDM", "IT"]
# DEMO documents on the domain controller's file shares (share -> file -> text). Umum: all staff; Keuangan: finance only.
SHARE_DOCS = {
    "Umum": {"Pengumuman-Kantor.txt": "DEMO - Pengumuman: rapat bulanan setiap Senin pukul 09.00.\n",
             "Daftar-Ekstensi-Telepon.txt": "DEMO - Resepsionis 100, IT 200, Keuangan 300, SDM 400.\n",
             "Panduan-Cuti.txt": "DEMO - Ajukan cuti lewat portal intranet paling lambat 3 hari sebelumnya.\n"},
    "Keuangan": {"Anggaran-Q4-DEMO.csv": "pos,jumlah\noperasional,DEMO\npemasaran,DEMO\n",
                 "Rekap-Tagihan-DEMO.txt": "DEMO - Data contoh, bukan data keuangan sungguhan.\n"},
}


def seed() -> str:
    s = os.environ.get("CR_LAB_SEED", "")
    if not s:   # outside the platform (e.g. manual docker run): a random seed, so passwords are never predictable
        os.makedirs("/var/lib/cr", exist_ok=True)
        p = "/var/lib/cr/seed"
        if not os.path.exists(p):
            with open(p, "w") as f:
                f.write(os.urandom(24).hex())
        s = open(p).read().strip()
    return s


def password(user: str) -> str:
    h = hashlib.sha256(f"{seed()}:{user}".encode()).hexdigest()
    return f"Lab-{h[:6]}-{h[6:12].upper()}-{h[12:16]}!"   # meets AD complexity (upper, lower, digit, symbol)


def peers() -> dict:
    out = {}
    for part in os.environ.get("CR_PEERS", "").split(","):
        role, _, ip = part.partition("=")
        if role and ip:
            out.setdefault(role.strip(), []).append(ip.strip())
    return out


def my_ip() -> str:
    if os.environ.get("CR_IP"):     # Lab Kit VMs: the address on the lab network (the hostname resolves to loopback there)
        return os.environ["CR_IP"]
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time() * 1e6) % 1000000:06d}Z"


def emit(**ev) -> None:
    """Append one normalized event (CYBER RANGE `json` log format) to the telemetry file."""
    ev.setdefault("timestamp", now_iso())
    ev.setdefault("host", NODE)
    rec = {k: v for k, v in ev.items() if v not in (None, "")}
    line = json.dumps(rec, ensure_ascii=False)[:4000] + "\n"
    os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
    with open(EVENTS, "a", encoding="utf-8") as f:   # O_APPEND: short lines from several writers do not interleave
        f.write(line)


def secret_file(content: str, path: str) -> str:
    """Write a 0600 file for tools that would otherwise take a password on the command line (visible in /proc)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path
