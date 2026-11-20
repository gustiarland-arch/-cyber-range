"""Sigma import regression: a Sigma YAML rule must produce an internal rule that fires on the events it should and only
those. Sigma import shipped without tests; this locks in the mapping so detection stays faithful to the source rule."""
import pytest

from app.blueteam import sigma
from app.blueteam.rules import matches, validate_rule


def _rule(yaml_text):
    res = sigma.parse(yaml_text)
    assert len(res) == 1 and res[0]["ok"], res[0].get("error")
    r = res[0]["rule"]
    assert validate_rule(r["kind"], r["conditions"], r.get("threshold"), r.get("group_by")) == []
    return r


def test_proxy_sqli_rule_maps_to_message_and_fires():
    r = _rule("""
title: Web SQLi in proxy URI
logsource: {category: proxy}
detection:
  sel: {c-uri|contains: 'union select'}
  condition: sel
level: high
tags: [attack.t1190]
""")
    assert r["kind"] == "match" and r["mitre_technique"] == "T1190"
    assert matches(r["conditions"], {"category": "http", "message": "GET /?q=1 union select 2 HTTP/1.1"})
    assert not matches(r["conditions"], {"category": "http", "message": "GET /home HTTP/1.1"})  # benign
    assert not matches(r["conditions"], {"category": "dns", "message": "union select"})  # wrong logsource category


def test_value_list_is_or_and_endswith_wildcard():
    r = _rule("""
title: Suspicious TLD lookups
logsource: {category: dns}
detection:
  sel: {query: ['*.zip', '*.top']}
  condition: sel
level: medium
""")
    assert matches(r["conditions"], {"category": "dns", "host": "payload.cr-test.zip"})
    assert matches(r["conditions"], {"category": "dns", "host": "c2.example.top"})
    assert not matches(r["conditions"], {"category": "dns", "host": "example.com"})


def test_and_of_two_selections_with_negation():
    r = _rule("""
title: Failed auth not from admin
logsource: {category: authentication}
detection:
  sel: {outcome: failure}
  admin: {user: admin}
  condition: sel and not admin
level: low
""")
    assert matches(r["conditions"], {"category": "auth", "outcome": "failure", "user": "bob"})
    assert not matches(r["conditions"], {"category": "auth", "outcome": "failure", "user": "admin"})
    assert not matches(r["conditions"], {"category": "auth", "outcome": "success", "user": "bob"})


def test_count_aggregation_becomes_threshold():
    r = _rule("""
title: Port scan
logsource: {category: firewall}
detection:
  sel: {action: denied}
  condition: sel | count(dst_port) by src_ip > 15
  timeframe: 60s
level: medium
""")
    assert r["kind"] == "threshold"
    assert r["threshold"]["group_by"] == "src_ip" and r["threshold"]["distinct"] == "dst_port"
    assert r["threshold"]["count"] == 16 and r["threshold"]["window_seconds"] == 60


def test_unsupported_rule_is_reported_not_silently_dropped():
    res = sigma.parse("title: broken\ndetection:\n  condition: nosuchselection\n")
    assert res[0]["ok"] is False and res[0]["error"]


def test_multiple_documents_parsed_independently():
    res = sigma.parse(
        "title: A\nlogsource: {category: dns}\ndetection:\n  sel: {query|contains: evil}\n  condition: sel\n"
        "---\n"
        "title: B\ndetection:\n  condition: ghost\n"
    )
    assert len(res) == 2
    assert res[0]["ok"] is True and res[1]["ok"] is False
