"""Replay a captured packet capture (.pcap) into the SIEM as Zeek-style events.

Why this exists: without it, the only "network" evidence in a lab is what the platform's own red team actions write, so a
detection rule can look like it works while really matching the platform's own markers. A real .pcap -- recorded by the lab
sensors, exported from Wireshark, or downloaded from a public capture -- is independent ground truth. Replaying it produces
exactly the events a live Zeek sensor would (conn / dns / http records fed through app.blueteam.normalize.zeek), so a rule
that fires on a replay is a rule that fires on real traffic.

Deliberately dependency-free: a pure-Python reader for the classic libpcap format (Ethernet II / IPv4 / TCP-UDP-ICMP),
so the shipped app needs no scapy/dpkt. pcapng, IPv6 and link types other than Ethernet/raw-IPv4 are reported, not guessed.

Scope of what is extracted (the subset that maps onto the normalized model and the built-in rules):
  * conn  -- one record per transport flow (TCP/UDP) and per ICMP echo pair, with byte counts and a rough conn_state;
  * dns   -- the query name and type from UDP/53 requests;
  * http  -- the request line (method, host, URI) and User-Agent from cleartext HTTP on any port.
TLS/HTTPS payloads are encrypted, so only the conn record is produced for them (as with a real sensor)."""
import ipaddress
import struct
from collections import OrderedDict

MAX_BYTES = 50 * 1024 * 1024
MAX_PACKETS = 500_000
MAX_RECORDS = 50_000

# well-known ports -> Zeek-style service label (only a hint; normalization does not depend on it)
_SERVICE = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 123: "ntp",
            143: "imap", 389: "ldap", 443: "ssl", 445: "smb", 465: "smtp", 587: "smtp", 993: "imap", 995: "pop3",
            1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis", 8080: "http", 8443: "ssl", 27017: "mongo"}
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")
_DNS_QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY", 65: "HTTPS"}


class PcapError(ValueError):
    """The capture cannot be read or is in an unsupported format (message is safe to show the user)."""


def _packets(data: bytes):
    """Yield (timestamp_seconds, frame_bytes) for a classic libpcap file. Raises PcapError on anything unsupported."""
    if len(data) < 24:
        raise PcapError("file terlalu pendek untuk sebuah pcap")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raise PcapError("format pcapng belum didukung; ekspor sebagai 'Wireshark/tcpdump pcap' (classic .pcap)")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    else:
        raise PcapError("bukan file pcap yang dikenal (magic number tidak cocok)")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype not in (1, 101):  # 1 = Ethernet, 101 = raw IPv4
        raise PcapError(f"link type {linktype} belum didukung (hanya Ethernet dan raw IPv4)")
    off, n, div = 24, 0, (1e9 if nano else 1e6)
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > 262144 or off + incl > len(data):
            break
        frame = data[off:off + incl]
        off += incl
        n += 1
        if n > MAX_PACKETS:
            raise PcapError(f"capture melebihi {MAX_PACKETS} paket")
        # raw IPv4 (101): prepend a synthetic Ethernet header with the IPv4 ethertype so _ipv4() parses it uniformly
        yield ts_sec + ts_frac / div, (b"\x00" * 12 + b"\x08\x00" + frame if linktype == 101 else frame)


def _ipv4(frame: bytes):
    """Return (proto, src_ip, dst_ip, l4_payload) for an IPv4 Ethernet frame, or None for anything else."""
    if len(frame) < 14:
        return None
    etype = frame[12] << 8 | frame[13]
    ihl_off = 14
    if etype == 0x8100:  # 802.1Q VLAN tag
        if len(frame) < 18:
            return None
        etype = frame[16] << 8 | frame[17]
        ihl_off = 18
    if etype != 0x0800:  # not IPv4 (IPv6 0x86DD and ARP are skipped on purpose)
        return None
    ip = frame[ihl_off:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = ip[2] << 8 | ip[3]
    proto = ip[9]
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    payload = ip[ihl:total] if 0 < total <= len(ip) else ip[ihl:]
    return proto, src, dst, payload


def _dns_query(payload: bytes):
    """(qname, qtype_name) from a DNS request payload, or None. Only the first question, compression-free (requests are)."""
    if len(payload) < 12:
        return None
    qd = payload[4] << 8 | payload[5]
    if qd < 1 or (payload[2] & 0x80):  # QR bit set = response, skip
        return None
    off, labels = 12, []
    for _ in range(64):
        if off >= len(payload):
            return None
        ln = payload[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 or off + 1 + ln > len(payload):
            return None
        labels.append(payload[off + 1:off + 1 + ln].decode("latin-1"))
        off += 1 + ln
    if off + 4 > len(payload):
        return None
    qtype = payload[off] << 8 | payload[off + 1]
    return ".".join(labels) or ".", _DNS_QTYPE.get(qtype, str(qtype))


def _http_request(payload: bytes):
    """(method, uri, host, user_agent) from a cleartext HTTP request payload, or None."""
    if not payload.startswith(_HTTP_METHODS):
        return None
    head = payload[:8192].split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) < 3 or not parts[2].startswith(b"HTTP/"):
        return None
    method, uri = parts[0].decode("latin-1"), parts[1].decode("latin-1")
    host = ua = None
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith(b"host:"):
            host = ln[5:].strip().decode("latin-1")
        elif low.startswith(b"user-agent:"):
            ua = ln[11:].strip().decode("latin-1")
    return method, uri, host, ua


class _Flow:
    __slots__ = ("proto", "orig_h", "orig_p", "resp_h", "resp_p", "service", "ts", "last", "orig_bytes", "resp_bytes",
                 "pkts", "syn", "synack", "fin", "rst")

    def __init__(self, proto, sh, sp, dh, dp, ts):
        self.proto, self.orig_h, self.orig_p, self.resp_h, self.resp_p = proto, sh, sp, dh, dp
        self.service = _SERVICE.get(dp) or _SERVICE.get(sp)
        self.ts = self.last = ts
        self.orig_bytes = self.resp_bytes = self.pkts = 0
        self.syn = self.synack = self.fin = self.rst = False

    def conn_state(self):
        # a small, honest subset of Zeek's conn_state: enough for a human to read, not a full state machine
        if self.proto == "tcp":
            if self.rst:
                return "RSTO" if self.synack else "REJ"
            if self.syn and not self.synack:
                return "S0"
            if self.fin:
                return "SF"
            return "OTH" if not self.synack else "S1"
        return "SF"


def to_zeek_records(data: bytes, *, shift_to_now: bool = True, now: float | None = None) -> dict:
    """Parse a classic .pcap into Zeek-style records (conn / dns / http). Returns {records, stats}.

    shift_to_now keeps each packet's position relative to the others but moves the whole capture so its last packet is at
    `now`, so a replay lands inside the live SIEM window instead of at the capture's original (possibly old) date."""
    import time as _time
    if len(data) > MAX_BYTES:
        raise PcapError(f"file melebihi {MAX_BYTES // (1024 * 1024)} MB")
    flows: "OrderedDict[tuple, _Flow]" = OrderedDict()
    extras = []  # (ts, record) for dns/http, emitted in capture order
    first_ts = last_ts = None
    stats = {"packets": 0, "ipv4": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "http": 0, "other": 0}
    for ts, frame in _packets(data):
        stats["packets"] += 1
        first_ts = ts if first_ts is None else first_ts
        last_ts = ts
        parsed = _ipv4(frame)
        if not parsed:
            stats["other"] += 1
            continue
        stats["ipv4"] += 1
        proto, src, dst, l4 = parsed
        if proto == 6 and len(l4) >= 20:  # TCP
            stats["tcp"] += 1
            sp, dp = l4[0] << 8 | l4[1], l4[2] << 8 | l4[3]
            doff = (l4[12] >> 4) * 4
            flags = l4[13]
            body = l4[doff:] if 0 < doff <= len(l4) else b""
            fl = _flow_for(flows, "tcp", src, sp, dst, dp, ts)
            fl.pkts += 1
            (setattr(fl, "orig_bytes", fl.orig_bytes + len(body)) if (src, sp) == (fl.orig_h, fl.orig_p)
             else setattr(fl, "resp_bytes", fl.resp_bytes + len(body)))
            if flags & 0x02:
                fl.synack = True if flags & 0x10 else fl.synack
                fl.syn = True if not (flags & 0x10) else fl.syn
            fl.fin = fl.fin or bool(flags & 0x01)
            fl.rst = fl.rst or bool(flags & 0x04)
            if body:
                req = _http_request(body)
                if req and len(extras) < MAX_RECORDS:
                    stats["http"] += 1
                    m, uri, host, ua = req
                    extras.append((ts, {"_path": "http", "id.orig_h": src, "id.orig_p": sp, "id.resp_h": dst, "id.resp_p": dp,
                                        "method": m, "uri": uri, "host": host, "user_agent": ua}))
        elif proto == 17 and len(l4) >= 8:  # UDP
            stats["udp"] += 1
            sp, dp = l4[0] << 8 | l4[1], l4[2] << 8 | l4[3]
            body = l4[8:]
            fl = _flow_for(flows, "udp", src, sp, dst, dp, ts)
            fl.pkts += 1
            (setattr(fl, "orig_bytes", fl.orig_bytes + len(body)) if (src, sp) == (fl.orig_h, fl.orig_p)
             else setattr(fl, "resp_bytes", fl.resp_bytes + len(body)))
            if dp == 53 or sp == 53:
                q = _dns_query(body)
                if q and len(extras) < MAX_RECORDS:
                    stats["dns"] += 1
                    extras.append((ts, {"_path": "dns", "id.orig_h": src, "id.orig_p": sp, "id.resp_h": dst, "id.resp_p": dp,
                                        "proto": "udp", "query": q[0], "qtype_name": q[1]}))
        elif proto == 1 and len(l4) >= 4:  # ICMP
            stats["icmp"] += 1
            if l4[0] == 8:  # echo request -> a conn record so host-sweep detection sees it
                fl = _flow_for(flows, "icmp", src, 0, dst, 0, ts)
                fl.pkts += 1
        else:
            stats["other"] += 1
        if len(flows) > MAX_RECORDS:
            break
        fl.last = ts

    shift = (now if now is not None else _time.time()) - last_ts if (shift_to_now and last_ts is not None) else 0.0
    records = []
    for fl in flows.values():
        records.append((fl.ts, {"_path": "conn", "id.orig_h": fl.orig_h, "id.orig_p": fl.orig_p, "id.resp_h": fl.resp_h,
                                "id.resp_p": fl.resp_p, "proto": fl.proto, "service": fl.service, "conn_state": fl.conn_state(),
                                "orig_bytes": fl.orig_bytes, "resp_bytes": fl.resp_bytes, "duration": round(fl.last - fl.ts, 6)}))
    records.extend(extras)
    records.sort(key=lambda r: r[0])
    out = []
    for ts, rec in records[:MAX_RECORDS]:
        rec["ts"] = round(ts + shift, 6)
        out.append(rec)
    stats["records"] = len(out)
    stats["duration_seconds"] = round((last_ts - first_ts), 3) if first_ts is not None else 0.0
    return {"records": out, "stats": stats}


def _flow_for(flows, proto, sh, sp, dh, dp, ts) -> _Flow:
    """Return the flow this packet belongs to, keyed independent of direction (orig = the side seen first)."""
    fwd = (proto, sh, sp, dh, dp)
    rev = (proto, dh, dp, sh, sp)
    if fwd in flows:
        return flows[fwd]
    if rev in flows:
        return flows[rev]
    fl = _Flow(proto, sh, sp, dh, dp, ts)
    flows[fwd] = fl
    return fl
