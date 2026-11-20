"""PCAP replay (1.9.0): a classic .pcap becomes Zeek-style events that the built-in rules fire on, so detection is proven
against real packet bytes rather than the platform's own red team markers.

The capture fixtures are built from raw bytes here, so these unit tests need no scapy/dpkt (same philosophy as the reader)."""
import os
import struct

import pytest

from app.blueteam import normalize as norm
from app.blueteam.pcap_replay import PcapError, to_zeek_records
from app.blueteam.rules import BUILTIN_RULES, matches

RULES = {r["code"]: r for r in BUILTIN_RULES}


# ----------------------------------------------------------------- raw frame / pcap builders (no dependencies)
def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + payload


def _ipv4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    sip = bytes(int(x) for x in src.split("."))
    dip = bytes(int(x) for x in dst.split("."))
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, proto, 0) + sip + dip
    return hdr + payload


def _tcp(sp: int, dp: int, payload: bytes = b"", flags: int = 0x02) -> bytes:
    return struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 0x50, flags, 0, 0, 0) + payload


def _udp(sp: int, dp: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload


def _icmp_echo() -> bytes:
    return struct.pack(">BBHHH", 8, 0, 0, 1, 1)


def _dns_q(name: str, qtype: int = 1) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def _pcap(frames: list[bytes], base_ts: int = 1_700_000_000) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)  # little-endian, Ethernet
    for i, fr in enumerate(frames):
        out += struct.pack("<IIII", base_ts + i, i * 1000, len(fr), len(fr)) + fr
    return out


def _events(data: bytes):
    parsed = to_zeek_records(data, shift_to_now=False)
    return parsed, [norm.zeek(r) for r in parsed["records"]]


# ----------------------------------------------------------------- tests
def test_port_scan_pcap_fires_service_scan_rule():
    frames = [_eth(_ipv4(6, "10.9.9.9", "10.9.9.20", _tcp(40000 + p, p))) for p in
              (21, 22, 23, 25, 80, 110, 143, 443, 445, 3306)]
    parsed, evs = _events(_pcap(frames))
    assert parsed["stats"]["tcp"] == 10 and parsed["stats"]["records"] == 10
    ports = {e["dst_port"] for e in evs if e.get("src_ip") == "10.9.9.9" and e.get("dst_port")}
    assert len(ports) == 10  # CR-NET-003 threshold is 8 distinct ports
    scan = next(e for e in evs if e["dst_port"] == 3306)
    assert matches(RULES["CR-NET-003"]["conditions"], scan)
    assert "S0" in scan["message"] and "mysql" in scan["message"]  # SYN-only, service guessed


def test_icmp_sweep_pcap_fires_host_sweep_rule():
    frames = [_eth(_ipv4(1, "10.9.9.9", f"10.9.9.{h}", _icmp_echo())) for h in range(10, 15)]
    parsed, evs = _events(_pcap(frames))
    assert parsed["stats"]["icmp"] == 5
    icmp = [e for e in evs if e.get("protocol") == "icmp"]
    assert len({e["dst_ip"] for e in icmp}) == 5  # CR-NET-002 threshold is 4
    assert all(matches(RULES["CR-NET-002"]["conditions"], e) for e in icmp)


def test_http_request_pcap_fires_web_attack_rule_on_real_uri():
    payload = b"GET /?id=1%20union%20select%20null--x HTTP/1.1\r\nHost: web.lab\r\nUser-Agent: sqlmap/1.7\r\n\r\n"
    frames = [_eth(_ipv4(6, "10.9.9.9", "10.9.9.20", _tcp(51000, 80, payload, flags=0x18)))]
    parsed, evs = _events(_pcap(frames))
    http = [e for e in evs if e.get("category") == "http"]
    assert len(http) == 1
    assert matches(RULES["CR-WEB-001"]["conditions"], http[0])  # fires on the captured URI, not a cr-test marker
    assert "union" in http[0]["message"] and "web.lab" in http[0]["message"]


def test_dns_query_pcap_extracts_name_and_type():
    frames = [_eth(_ipv4(17, "10.9.9.9", "10.9.9.1", _udp(5353, 53, _dns_q("payload.cr-test.zip"))))]
    parsed, evs = _events(_pcap(frames))
    dns = [e for e in evs if e.get("category") == "dns"]
    assert len(dns) == 1 and dns[0]["host"] == "payload.cr-test.zip"
    assert matches(RULES["CR-DNS-001"]["conditions"], dns[0])


def test_flow_is_direction_independent():
    """A request and its reply are one conn record, with bytes attributed to the right side."""
    req = _eth(_ipv4(6, "10.1.0.5", "10.1.0.9", _tcp(5000, 80, b"GET / HTTP/1.0\r\n\r\n", flags=0x18)))
    rep = _eth(_ipv4(6, "10.1.0.9", "10.1.0.5", _tcp(80, 5000, b"HTTP/1.0 200 OK\r\n\r\n", flags=0x18)))
    parsed, _ = _events(_pcap([req, rep]))
    conns = [r for r in parsed["records"] if r["_path"] == "conn"]
    assert len(conns) == 1
    assert conns[0]["orig_bytes"] > 0 and conns[0]["resp_bytes"] > 0


def test_shift_to_now_moves_capture_into_window():
    frames = [_eth(_ipv4(6, "10.0.0.1", "10.0.0.2", _tcp(1234, 80)))]
    now = 2_000_000_000.0
    recs = to_zeek_records(_pcap(frames, base_ts=1_000_000_000), shift_to_now=True, now=now)["records"]
    assert abs(recs[0]["ts"] - now) < 1.0  # last packet lands at `now`, not the capture's old date


def test_pcapng_is_reported_not_guessed():
    with pytest.raises(PcapError) as e:
        to_zeek_records(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    assert "pcapng" in str(e.value).lower()


def test_non_pcap_bytes_rejected():
    with pytest.raises(PcapError):
        to_zeek_records(b"this is not a pcap file at all........")


def test_raw_ipv4_linktype_supported():
    # link type 101 (raw IPv4, no Ethernet header)
    ip = _ipv4(1, "10.0.0.1", "10.0.0.2", _icmp_echo())
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 101)
    body = struct.pack("<IIII", 1_700_000_000, 0, len(ip), len(ip)) + ip
    parsed, evs = _events(hdr + body)
    assert parsed["stats"]["icmp"] == 1 and evs[0]["protocol"] == "icmp"


def test_empty_capture_yields_no_records():
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    parsed = to_zeek_records(hdr)
    assert parsed["records"] == [] and parsed["stats"]["packets"] == 0


# ----------------------------------------------------------------- endpoint (needs the migrated test DB)
def _db_available():
    if not os.environ.get("CR_TEST_MYSQL_DATABASE"):
        return False
    try:
        from sqlalchemy import text

        from app.core.database import SessionLocal
        with SessionLocal() as db:
            db.execute(text("select 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


integration = pytest.mark.skipif(not _db_available(), reason="set CR_TEST_MYSQL_DATABASE to a migrated test database")


@integration
def test_replay_endpoint_ingests_and_detects():
    from fastapi.testclient import TestClient

    from app.main import app
    client = TestClient(app, base_url="http://localhost")
    tok = client.post("/api/v1/auth/local").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    frames = [_eth(_ipv4(6, "10.77.0.9", "10.77.0.20", _tcp(40000 + p, p))) for p in
              (21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080)]
    pcap = _pcap(frames)
    r = client.post("/api/v1/soc/pcap/replay", headers=h, files={"file": ("scan.pcap", pcap, "application/vnd.tcpdump.pcap")},
                    data={"shift_to_now": "true"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stats"]["tcp"] == 12 and body["accepted"] >= 12
    # the replayed scan is now queryable in the SIEM as zeek.conn events from the capture's source IP
    ev = client.get("/api/v1/soc/events", headers=h, params={"q": "src:10.77.0.9 dataset:zeek.conn", "page_size": 50}).json()
    assert ev["total"] >= 12
