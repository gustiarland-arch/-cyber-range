"""Regression tests for the 1.6.0 security fixes (no database or Docker needed)."""
import ipaddress
import time

import pytest

from app.cyber_range.engine.planner import MIN_PREFIX, PlanError, _top_hosts, build_plan
from app.redteam.actions import MAX_HOSTS, build_command
from app.terminal.gateway import _size

IMAGES = [{"reference": "alpine:3.20", "is_enabled": True, "node_types": ["server"], "command": None, "tmpfs": [], "cap_add": [],
           "default_cpus": 0.25, "default_memory_mb": 64}]


def doc(cidr: str) -> dict:
    return {"zones": [], "links": [],
            "subnets": [{"key": "s1", "name": "Net", "cidr": cidr, "gateway": None, "zone": None}],
            "nodes": [{"key": "n1", "type": "server", "label": "Web", "position": {"x": 0, "y": 0},
                       "interfaces": [{"name": "eth0", "subnet": "s1", "ip": None}]}]}


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "10.0.0.0/12", "172.16.0.0/15"])
def test_planner_rejects_huge_subnets_quickly(cidr):
    t = time.monotonic()
    with pytest.raises(PlanError) as e:
        build_plan(doc(cidr), IMAGES)
    assert time.monotonic() - t < 1.0
    assert any(f"min /{MIN_PREFIX}" in p for p in e.value.problems)


@pytest.mark.parametrize("cidr", ["10.10.0.0/16", "10.10.0.0/24", "10.0.0.0/29"])
def test_planner_still_accepts_normal_subnets(cidr):
    plan = build_plan(doc(cidr), IMAGES)
    assert plan["totals"]["containers"] == 1


@pytest.mark.parametrize("cidr", ["10.10.0.0/24", "10.0.0.0/28", "10.0.0.0/29", "10.10.0.0/16"])
def test_top_hosts_matches_reference(cidr):
    net = ipaddress.ip_network(cidr)
    hosts = list(net.hosts())
    assert _top_hosts(net, 64) == [str(h) for h in reversed(hosts[-64:])]


def test_host_discovery_never_materialises_large_networks():
    t = time.monotonic()
    argv, _ = build_command("host_discovery", {}, [], ["10.0.0.0/8"])
    assert time.monotonic() - t < 0.5
    assert argv[2].count("10.") == MAX_HOSTS


@pytest.mark.parametrize("value,expected", [("abc", 100), (None, 100), ("", 100), (True, 100), ([1], 100), ({}, 100),
                                            ("120", 120), (10**9, 400), (-5, 20), (3.7, 20), (250, 250)])
def test_terminal_size_is_validated(value, expected):
    assert _size(value, 100, 20, 400) == expected


def test_local_token_setting_validation(monkeypatch):
    from app.core.config import Settings
    monkeypatch.setenv("CR_LOCAL_ACCESS_TOKEN", "short")
    with pytest.raises(ValueError):
        Settings()
    monkeypatch.setenv("CR_LOCAL_ACCESS_TOKEN", "bad token with spaces and enough length")
    with pytest.raises(ValueError):
        Settings()
    monkeypatch.setenv("CR_LOCAL_ACCESS_TOKEN", "A" * 24)
    assert Settings().local_access_token.get_secret_value() == "A" * 24
    monkeypatch.setenv("CR_LOCAL_ACCESS_TOKEN", "")
    assert Settings().local_access_token.get_secret_value() == ""
