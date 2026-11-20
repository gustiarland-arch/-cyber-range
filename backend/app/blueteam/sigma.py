"""Convert Sigma rules (https://github.com/SigmaHQ/sigma, YAML) into CYBER RANGE detection rules.

Scope: the subset of Sigma that maps onto the normalized event model (network, IDS, auth, DNS, HTTP, host logs):
  * detection maps (AND of fields) and lists of maps (OR); value lists are OR, `|all` makes them AND;
  * modifiers contains, startswith, endswith, re, cidr, gt/gte/lt/lte, all, plus keyword lists (searched in `message`);
  * conditions with and / or / not, parentheses, `1 of sel*`, `all of sel*`, `1 of them`, `all of them`;
  * the legacy aggregation `<selection> | count([field]) by <field> > N` with `timeframe` becomes a threshold rule;
  * logsource category/product/service adds dataset/category conditions; level -> severity; attack.* tags -> MITRE.
Anything outside that subset (unknown fields, `near`, other aggregations, correlation rules) is reported as an error for
that rule instead of being dropped silently, so an imported rule never matches something different from its source.
"""
import hashlib
import re

import yaml

from app.blueteam.attack import TECH_RX, tactic_from_tag, tactics_for
from app.blueteam.rules import GROUP_FIELDS, validate_rule

MAX_DOCS = 50
MAX_SOURCE = 200_000

FIELD_MAP = {
    "src_ip": "src_ip", "sourceip": "src_ip", "source.ip": "src_ip", "id.orig_h": "src_ip", "srcip": "src_ip", "c-ip": "src_ip", "clientip": "src_ip",
    "dst_ip": "dst_ip", "destinationip": "dst_ip", "destination.ip": "dst_ip", "id.resp_h": "dst_ip", "dest_ip": "dst_ip", "dstip": "dst_ip", "s-ip": "dst_ip",
    "src_port": "src_port", "sourceport": "src_port", "source.port": "src_port", "id.orig_p": "src_port", "srcport": "src_port",
    "dst_port": "dst_port", "destinationport": "dst_port", "destination.port": "dst_port", "id.resp_p": "dst_port", "dest_port": "dst_port",
    "dstport": "dst_port", "s-port": "dst_port",
    "user": "user", "username": "user", "user.name": "user", "targetusername": "user", "subjectusername": "user", "dstuser": "user", "srcuser": "user",
    "host": "host", "hostname": "host", "computer": "host", "computername": "host", "host.name": "host", "cs-host": "host", "query": "host",
    "queryname": "host", "dns.question.name": "host", "rrname": "host", "server_name": "host", "sni": "host", "r-dns": "host",
    "protocol": "protocol", "proto": "protocol", "network.protocol": "protocol", "app_proto": "protocol", "service": "protocol",
    "signature": "signature", "alert.signature": "signature", "rule.description": "signature", "note": "signature",
    "signature_id": "signature_id", "alert.signature_id": "signature_id", "sid": "signature_id", "rule.id": "signature_id", "eventid": "signature_id",
    "action": "action", "cs-method": "action", "method": "action", "http_method": "action", "event.action": "action",
    "outcome": "outcome", "sc-status": "outcome", "status_code": "outcome", "event.outcome": "outcome",
    "category": "category", "dataset": "dataset", "severity": "severity",
    # free-text fields are matched against the normalized message (which carries URI, user agent, command line, log text)
    "message": "message", "msg": "message", "full_log": "message", "commandline": "message", "image": "message", "cs-uri-query": "message",
    "cs-uri-stem": "message", "c-uri": "message", "c-uri-query": "message", "uri": "message", "url": "message", "c-useragent": "message",
    "user_agent": "message", "useragent": "message", "keywords": "message", "payload": "message", "parentcommandline": "message",
}
FREE_TEXT = "message"
LOGSOURCE = {
    ("category", "firewall"): [{"field": "category", "op": "in", "value": ["network", "ids"]}],
    ("category", "network_connection"): [{"field": "category", "op": "eq", "value": "network"}],
    ("category", "dns"): [{"field": "category", "op": "eq", "value": "dns"}],
    ("category", "webserver"): [{"field": "category", "op": "eq", "value": "http"}],
    ("category", "proxy"): [{"field": "category", "op": "eq", "value": "http"}],
    ("category", "ids"): [{"field": "category", "op": "eq", "value": "ids"}],
    ("category", "authentication"): [{"field": "category", "op": "eq", "value": "auth"}],
    ("product", "zeek"): [{"field": "dataset", "op": "startswith", "value": "zeek."}],
    ("product", "suricata"): [{"field": "dataset", "op": "startswith", "value": "suricata."}],
    ("product", "wazuh"): [{"field": "dataset", "op": "eq", "value": "wazuh.alert"}],
    ("service", "sshd"): [{"field": "protocol", "op": "eq", "value": "ssh"}],
    ("service", "auth"): [{"field": "category", "op": "eq", "value": "auth"}],
    ("service", "sudo"): [{"field": "action", "op": "eq", "value": "sudo"}],
    ("service", "syslog"): [{"field": "dataset", "op": "startswith", "value": "syslog."}],
    ("service", "dns"): [{"field": "category", "op": "eq", "value": "dns"}],
    ("service", "http"): [{"field": "category", "op": "eq", "value": "http"}],
    ("service", "conn"): [{"field": "dataset", "op": "eq", "value": "zeek.conn"}],
    ("service", "notice"): [{"field": "dataset", "op": "eq", "value": "zeek.notice"}],
}
IGNORED_LOGSOURCE = {("product", "linux"), ("product", "windows"), ("product", "apache"), ("product", "nginx"), ("category", "application")}
LEVEL = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
NUMERIC = {"severity", "src_port", "dst_port"}


class SigmaError(ValueError):
    pass


def _wild_to_regex(v: str) -> str:
    out = []
    for ch in v:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return "".join(out)


def _leaf(field: str, mods: list[str], value) -> dict:
    if value is None:
        return {"field": field, "op": "exists", "value": False}
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        if not isinstance(value, int | float):
            raise SigmaError(f"{field}: numeric modifier needs a number")
        m = next(m for m in mods if m in ("gt", "gte", "lt", "lte"))
        v = value + 1 if m == "gt" and isinstance(value, int) else value - 1 if m == "lt" and isinstance(value, int) else value
        return {"field": field, "op": "gte" if m in ("gt", "gte") else "lte", "value": v}
    if "cidr" in mods:
        return {"field": field, "op": "cidr", "value": str(value)}
    if "re" in mods:
        return {"field": field, "op": "regex", "value": str(value)}
    s = str(value)
    if field in NUMERIC and isinstance(value, int):
        return {"field": field, "op": "eq", "value": value}
    if "contains" in mods:
        return {"field": field, "op": "contains", "value": s}
    if "startswith" in mods:
        return {"field": field, "op": "startswith", "value": s}
    if "endswith" in mods:
        return {"field": field, "op": "regex", "value": re.escape(s) + "$"}
    if "*" in s or "?" in s:
        core = s.strip("*")
        if s.startswith("*") and s.endswith("*") and "*" not in core and "?" not in core:
            return {"field": field, "op": "contains", "value": core}
        if s.endswith("*") and "*" not in s[:-1] and "?" not in s:
            return {"field": field, "op": "startswith", "value": s[:-1]}
        return {"field": field, "op": "regex", "value": "^" + _wild_to_regex(s) + "$"}
    return {"field": field, "op": "eq", "value": s}


def _field_conditions(key: str, value) -> list[dict]:
    name, *mods = key.split("|")
    mods = [m.lower() for m in mods]
    unsupported = set(mods) - {"contains", "startswith", "endswith", "re", "cidr", "all", "gt", "gte", "lt", "lte", "i"}
    if unsupported:
        raise SigmaError(f"field {name}: unsupported modifier(s) {', '.join(sorted(unsupported))}")
    field = FIELD_MAP.get(name.lower())
    if not field:
        raise SigmaError(f"field '{name}' has no equivalent in the normalized event model")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"field {name}: empty value list")
    leaves = [_leaf(field, mods, v) for v in values]
    if len(leaves) == 1 or "all" in mods:
        return leaves
    if all(lf["op"] == "eq" for lf in leaves):
        return [{"field": field, "op": "in", "value": [lf["value"] for lf in leaves]}]
    return [{"op": "any_of", "value": [[lf] for lf in leaves]}]


def _selection(name: str, body) -> list[dict]:
    """A named detection item -> list of AND-ed conditions (possibly containing any_of groups)."""
    if isinstance(body, dict):
        out = []
        for k, v in body.items():
            out += _field_conditions(str(k), v)
        return out
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        return [{"op": "any_of", "value": [_selection(name, x) for x in body]}] if len(body) > 1 else _selection(name, body[0])
    if isinstance(body, list | str | int):
        words = body if isinstance(body, list) else [body]
        leaves = [_leaf(FREE_TEXT, ["contains"], str(w).strip("*")) for w in words]
        return leaves if len(leaves) == 1 else [{"op": "any_of", "value": [[lf] for lf in leaves]}]
    raise SigmaError(f"detection item '{name}' has an unsupported shape")


# ------------------------------------------------------------------ condition parser
_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[A-Za-z0-9_*]+)", re.I)


def _tokens(cond: str) -> list[str]:
    pos, out = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = _TOK.match(cond, pos)
        if not m:
            raise SigmaError(f"cannot parse condition near '{cond[pos:pos + 20]}'")
        out.append(m.group(1).lower() if m.group(1).lower() in ("and", "or", "not", "1 of", "all of") else m.group(1))
        pos = m.end()
    return out


def _parse_condition(cond: str, sels: dict[str, list[dict]]) -> list[dict]:
    toks = _tokens(cond)
    i = 0

    def names(pattern: str) -> list[str]:
        if pattern == "them":
            ns = [n for n in sels if not n.startswith("_")]
        else:
            rx = re.compile("^" + _wild_to_regex(pattern) + "$")
            ns = [n for n in sels if rx.match(n)]
        if not ns:
            raise SigmaError(f"condition refers to unknown selection '{pattern}'")
        return ns

    def primary() -> list[dict]:
        nonlocal i
        if i >= len(toks):
            raise SigmaError("condition ends unexpectedly")
        t = toks[i]
        if t == "(":
            i += 1
            r = expr()
            if i >= len(toks) or toks[i] != ")":
                raise SigmaError("missing ')' in condition")
            i += 1
            return r
        if t == "not":
            i += 1
            return [{"op": "none_of", "value": [primary()]}]
        if t in ("1 of", "all of"):
            i += 1
            ns = names(toks[i])
            i += 1
            groups = [sels[n] for n in ns]
            if t == "all of":
                return [c for g in groups for c in g]
            return groups[0] if len(groups) == 1 else [{"op": "any_of", "value": groups}]
        if t in sels:
            i += 1
            return list(sels[t])
        raise SigmaError(f"condition refers to unknown selection '{t}'")

    def term() -> list[dict]:
        nonlocal i
        out = primary()
        while i < len(toks) and toks[i] == "and":
            i += 1
            out = out + primary()
        return out

    def expr() -> list[dict]:
        nonlocal i
        parts = [term()]
        while i < len(toks) and toks[i] == "or":
            i += 1
            parts.append(term())
        return parts[0] if len(parts) == 1 else [{"op": "any_of", "value": parts}]

    res = expr()
    if i != len(toks):
        raise SigmaError(f"unexpected '{toks[i]}' in condition")
    return res


_AGG = re.compile(r"^(.*)\|\s*count\(\s*([A-Za-z0-9_.\-]*)\s*\)\s*(?:by\s+([A-Za-z0-9_.\-]+))?\s*(>=|>)\s*(\d+)\s*$", re.I)


def _timeframe(tf) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(tf or "").strip())
    if not m:
        raise SigmaError("aggregation needs a timeframe like 60s, 5m or 1h")
    return int(m[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]


def _code(doc: dict, title: str) -> str:
    rid = str(doc.get("id") or "")
    h = (re.sub(r"[^0-9a-fA-F]", "", rid)[:8] or hashlib.sha256(title.encode()).hexdigest()[:8]).upper()
    return f"SIGMA-{h}"


def convert(doc: dict) -> dict:
    if not isinstance(doc, dict):
        raise SigmaError("a Sigma rule must be a YAML mapping")
    if "correlation" in doc:
        raise SigmaError("Sigma correlation rules are not supported; use a threshold rule instead")
    title = str(doc.get("title") or "").strip()
    if not title:
        raise SigmaError("the rule has no title")
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("the rule has no detection/condition")
    warnings = []
    sels = {str(k): _selection(str(k), v) for k, v in det.items() if k not in ("condition", "timeframe")}
    cond = det["condition"]
    if isinstance(cond, list):
        if len(cond) != 1:
            raise SigmaError("multiple conditions in one rule are not supported; split the rule")
        cond = cond[0]
    cond = str(cond)
    if re.search(r"\bnear\b", cond, re.I):
        raise SigmaError("the 'near' aggregation is not supported")
    threshold = None
    m = _AGG.match(cond)
    if "|" in cond and not m:
        raise SigmaError("only `| count([field]) by <field> > N` aggregations are supported")
    if m:
        cond, distinct, by, cmp_, n = m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5))
        group = FIELD_MAP.get((by or "").lower())
        if group not in GROUP_FIELDS:
            raise SigmaError(f"aggregation must group by one of {', '.join(GROUP_FIELDS)} (got {by or 'nothing'})")
        threshold = {"count": max(2, n + 1 if cmp_ == ">" else n), "window_seconds": _timeframe(det.get("timeframe") or doc.get("timeframe")), "group_by": group}
        if distinct:
            df = FIELD_MAP.get(distinct.lower())
            if not df:
                raise SigmaError(f"count() field '{distinct}' has no equivalent")
            threshold["distinct"] = df
    conditions = _parse_condition(cond, sels)
    ls = doc.get("logsource") or {}
    pre = []
    for k in ("category", "product", "service"):
        v = ls.get(k)
        if not v:
            continue
        key = (k, str(v).lower())
        if key in LOGSOURCE:
            pre += LOGSOURCE[key]
        elif key not in IGNORED_LOGSOURCE:
            warnings.append(f"logsource {k}={v} is not mapped; the rule is evaluated on all events")
    conditions = pre + conditions
    tags = [str(t).lower() for t in doc.get("tags") or []]
    techs = [t.removeprefix("attack.").upper() for t in tags if TECH_RX.match(t.removeprefix("attack."))]
    tactics = [x for x in (tactic_from_tag(t) for t in tags if t.startswith("attack.")) if x]
    technique = techs[0] if techs else None
    tactic = tactics[0] if tactics else (tactics_for(technique)[0] if technique and tactics_for(technique) else None)
    level = str(doc.get("level") or "medium").lower()
    if level not in LEVEL:
        warnings.append(f"unknown level '{level}', using medium")
    status = str(doc.get("status") or "")
    if status in ("deprecated", "unsupported"):
        warnings.append(f"the Sigma rule status is '{status}'")
    desc = str(doc.get("description") or "").strip()
    refs = [str(r) for r in doc.get("references") or []][:5]
    fps = [str(f) for f in doc.get("falsepositives") or []][:5]
    full_desc = desc + (("\n\nFalse positives: " + "; ".join(fps)) if fps else "") + (("\n\nReferences: " + " ".join(refs)) if refs else "")
    rule = {"code": _code(doc, title), "name": title[:128], "description": full_desc[:4000], "severity": LEVEL.get(level, 2),
            "kind": "threshold" if threshold else "match", "conditions": conditions, "threshold": threshold, "group_by": None if threshold else "src_ip",
            "mitre_tactic": tactic, "mitre_technique": technique if technique and re.fullmatch(r"T\d{4}(\.\d{3})?", technique) else None}
    errs = validate_rule(rule["kind"], rule["conditions"], rule["threshold"], rule["group_by"])
    if errs:
        raise SigmaError("; ".join(errs))
    return {"rule": rule, "warnings": warnings, "sigma_id": str(doc.get("id") or "") or None}


def parse(source: str) -> list[dict]:
    """Return one result per YAML document: {index, title, ok, rule?, warnings, error?}."""
    if len(source) > MAX_SOURCE:
        raise SigmaError(f"Sigma source is limited to {MAX_SOURCE // 1000} KB")
    try:
        docs = [d for d in yaml.safe_load_all(source) if d is not None]
    except yaml.YAMLError as e:
        raise SigmaError(f"invalid YAML: {str(e)[:300]}") from e
    if not docs:
        raise SigmaError("no Sigma rule found")
    if len(docs) > MAX_DOCS:
        raise SigmaError(f"at most {MAX_DOCS} rules per import")
    out = []
    for i, d in enumerate(docs):
        title = str(d.get("title") or f"rule {i + 1}") if isinstance(d, dict) else f"rule {i + 1}"
        try:
            r = convert(d)
            out.append({"index": i, "title": title, "ok": True, **r})
        except SigmaError as e:
            out.append({"index": i, "title": title, "ok": False, "error": str(e), "warnings": []})
    return out
