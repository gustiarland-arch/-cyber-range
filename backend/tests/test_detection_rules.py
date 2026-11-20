"""Built-in reconnaissance rules added in 1.8.0: valid, and matching the event shapes of Zeek, Suricata and the
platform's red team activity record (normalised field names)."""
import pytest

from app.blueteam.rules import BUILTIN_RULES, matches, validate_rule

RULES = {r["code"]: r for r in BUILTIN_RULES}
NEW = ("CR-NET-002", "CR-NET-003", "CR-WEB-003")


@pytest.mark.parametrize("code", NEW)
def test_new_rules_are_valid_and_mapped_to_attack(code):
    r = RULES[code]
    assert validate_rule(r["kind"], r["conditions"], r.get("threshold"), r.get("group_by")) == []
    assert r["mitre_technique"] and r["threshold"]["group_by"] == "src_ip"


@pytest.mark.parametrize("ev,expected", [
    ({"category": "network", "protocol": "icmp", "action": "icmp_echo", "dst_ip": "10.0.0.5"}, True),   # activity record
    ({"category": "network", "protocol": "icmp", "action": "OTH", "dst_ip": "10.0.0.5", "dst_port": 0}, True),  # zeek conn
    ({"category": "network", "protocol": "tcp", "action": "tcp_connect", "dst_port": 22}, False),
    ({"category": "dns", "protocol": "dns", "host": "x.top"}, False),
])
def test_host_sweep_matches_icmp_only(ev, expected):
    assert matches(RULES["CR-NET-002"]["conditions"], ev) is expected


@pytest.mark.parametrize("ev,expected", [
    ({"category": "network", "protocol": "tcp", "action": "tcp_connect", "dst_port": 3306}, True),  # activity record
    ({"category": "network", "protocol": "http", "action": "SF", "dst_port": 80}, True),           # zeek conn with service
    ({"category": "network", "protocol": "icmp", "dst_port": 0}, False),
    ({"category": "http", "protocol": "http", "dst_port": 80}, False),
])
def test_service_scan_counts_tcp_ports_not_icmp(ev, expected):
    assert matches(RULES["CR-NET-003"]["conditions"], ev) is expected


@pytest.mark.parametrize("outcome,expected", [("404", True), ("403", True), ("", True), ("200", False), ("304", False)])
def test_path_enumeration_ignores_successful_pages(outcome, expected):
    ev = {"category": "http", "outcome": outcome, "message": f"GET 10.0.0.1/admin {outcome}"}
    assert matches(RULES["CR-WEB-003"]["conditions"], ev) is expected


def test_thresholds_are_lower_than_the_legacy_port_scan_rule():
    """CR-NET-003 exists because the built-in scenarios scan 8-14 ports, below CR-NET-001's 20."""
    assert RULES["CR-NET-003"]["threshold"]["count"] < RULES["CR-NET-001"]["threshold"]["count"]
