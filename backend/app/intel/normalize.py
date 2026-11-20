"""Indicator parsing and normalization (manual entry, plain text lists, CSV, STIX 2.1 bundles)."""
import csv
import hashlib
import io
import ipaddress
import json
import re
from datetime import datetime

DOMAIN_RX = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253})$")
HEX = {"md5": 32, "sha1": 40, "sha256": 64}
STIX_RX = re.compile(r"\[\s*([a-z0-9-]+):(value|hashes\.'?(?:SHA-256|SHA-1|MD5)'?)\s*=\s*'([^']{1,2048})'\s*\]", re.IGNORECASE)
STIX_TYPES = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url", "email-addr": "email"}


class IndicatorError(ValueError):
    pass


def value_key(v: str) -> str:
    return v if len(v) <= 255 else "sha256:" + hashlib.sha256(v.encode()).hexdigest()


def detect_type(v: str) -> str:
    v = v.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "/" in v and not v.lower().startswith(("http://", "https://")):
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            pass
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in HEX.values():
        return {n: t for t, n in HEX.items()}[len(v)]
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if EMAIL_RX.match(v):
        return "email"
    if DOMAIN_RX.match(v.lower().rstrip(".")):
        return "domain"
    raise IndicatorError(f"cannot determine indicator type of {v[:80]!r}")


def normalize(t: str, v: str) -> str:
    """Return the canonical form used for matching; raises IndicatorError for invalid values."""
    v = (v or "").strip()
    if not v:
        raise IndicatorError("empty value")
    if t == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            raise IndicatorError(f"invalid IP address {v!r}") from None
    if t == "cidr":
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            raise IndicatorError(f"invalid CIDR {v!r}") from None
    if t in HEX:
        if not re.fullmatch(r"[0-9a-fA-F]{%d}" % HEX[t], v):
            raise IndicatorError(f"{t} must be {HEX[t]} hex characters")
        return v.lower()
    if t == "domain":
        d = v.lower().rstrip(".")
        try:
            d = d.encode("idna").decode()
        except UnicodeError:
            raise IndicatorError(f"invalid domain {v!r}") from None
        if not DOMAIN_RX.match(d):
            raise IndicatorError(f"invalid domain {v!r}")
        return d
    if t == "url":
        if not v.lower().startswith(("http://", "https://")) or len(v) > 2048 or any(c.isspace() for c in v):
            raise IndicatorError("URL must start with http:// or https:// and contain no spaces")
        scheme, rest = v.split("://", 1)
        host, _, path = rest.partition("/")
        return f"{scheme.lower()}://{host.lower()}" + (f"/{path}" if path or v.endswith("/") else "")
    if t == "email":
        m = EMAIL_RX.match(v)
        if not m:
            raise IndicatorError(f"invalid email {v!r}")
        return v.lower()
    raise IndicatorError(f"unknown indicator type {t!r}")


def _date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        raise IndicatorError(f"invalid date {s!r}") from None


def parse_text(text: str) -> tuple[list[dict], list[str]]:
    """One indicator per line, type auto-detected. '#' starts a comment."""
    items, errors = [], []
    for n, line in enumerate(text.splitlines(), 1):
        v = line.split("#", 1)[0].strip()
        if not v:
            continue
        v = v.replace("[.]", ".").replace("hxxp", "http")  # common defanging
        try:
            items.append({"type": detect_type(v), "value": v})
        except IndicatorError as e:
            errors.append(f"line {n}: {e}")
    return items, errors


def parse_csv(text: str) -> tuple[list[dict], list[str]]:
    """Header row required: value[,type,confidence,severity,tags,description,valid_until]. Tags separated by ';'."""
    items, errors = [], []
    rd = csv.DictReader(io.StringIO(text))
    if not rd.fieldnames or "value" not in [f.strip().lower() for f in rd.fieldnames]:
        return [], ["CSV needs a header row with at least a 'value' column"]
    for n, row in enumerate(rd, 2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        try:
            it = {"value": row["value"], "type": row.get("type") or detect_type(row["value"])}
            if row.get("confidence"):
                it["confidence"] = int(row["confidence"])
            if row.get("severity"):
                it["severity"] = int(row["severity"])
            if row.get("tags"):
                it["tags"] = [t.strip() for t in row["tags"].split(";") if t.strip()]
            if row.get("description"):
                it["description"] = row["description"]
            if row.get("valid_until"):
                it["valid_until"] = _date(row["valid_until"])
            items.append(it)
        except (IndicatorError, ValueError) as e:
            errors.append(f"row {n}: {e}")
    return items, errors


def parse_stix(text: str) -> tuple[list[dict], list[str]]:
    """STIX 2.1 bundle: 'indicator' objects with simple equality patterns ([ipv4-addr:value = '...'], file hashes, ...)."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        return [], [f"not valid JSON: {e}"]
    objs = doc.get("objects", []) if isinstance(doc, dict) else []
    items, errors = [], []
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "indicator":
            continue
        if o.get("pattern_type", "stix") != "stix":
            errors.append(f"{o.get('id')}: pattern_type {o.get('pattern_type')} not supported")
            continue
        found = STIX_RX.findall(o.get("pattern", ""))
        if not found:
            errors.append(f"{o.get('id')}: only simple equality patterns are supported")
            continue
        for obj_type, prop, val in found:
            if obj_type.lower() == "file":
                h = prop.split(".", 1)[1].strip("'").upper()
                t = {"SHA-256": "sha256", "SHA-1": "sha1", "MD5": "md5"}.get(h)
            else:
                t = STIX_TYPES.get(obj_type.lower())
                if t == "ip" and "/" in val:
                    t = "cidr"
            if not t:
                errors.append(f"{o.get('id')}: object type {obj_type} not supported")
                continue
            it = {"type": t, "value": val, "description": (o.get("description") or o.get("name") or "")[:2000],
                  "external_id": (o.get("id") or "")[:128] or None, "tags": [str(x) for x in (o.get("labels") or []) + (o.get("indicator_types") or [])][:20]}
            if isinstance(o.get("confidence"), int):
                it["confidence"] = max(0, min(100, o["confidence"]))
            try:
                it["valid_until"] = _date(o.get("valid_until"))
                if o.get("valid_from"):
                    it["first_seen"] = _date(o["valid_from"])
            except IndicatorError as e:
                errors.append(f"{o.get('id')}: {e}")
                continue
            items.append(it)
    if not objs:
        errors.append("no STIX objects found (expected a bundle with an 'objects' list)")
    return items, errors


MISP_TYPES = {"ip-src": "ip", "ip-dst": "ip", "domain": "domain", "hostname": "domain", "url": "url", "uri": None, "link": "url",
              "sha256": "sha256", "sha1": "sha1", "md5": "md5", "email-src": "email", "email-dst": "email", "email": "email",
              "ip-src|port": "ip", "ip-dst|port": "ip", "domain|ip": "domain", "filename|sha256": "sha256", "filename|sha1": "sha1",
              "filename|md5": "md5"}
MISP_THREAT = {"1": 4, "2": 3, "3": 2, "4": 1}   # threat_level_id: high, medium, low, undefined -> severity


def misp_attributes(attrs: list, event: dict | None = None) -> tuple[list[dict], list[str]]:
    items, errors = [], []
    ev = event or {}
    ev_tags = [t.get("name") for t in ev.get("Tag") or [] if isinstance(t, dict)]
    sev = MISP_THREAT.get(str(ev.get("threat_level_id") or "4"), 2)
    for a in attrs:
        if not isinstance(a, dict):
            continue
        typ = str(a.get("type") or "")
        if typ not in MISP_TYPES or MISP_TYPES[typ] is None:
            continue   # non-network attribute types (filenames, text, yara...) are not indicators here
        if a.get("to_ids") is False or str(a.get("to_ids")).lower() in ("0", "false"):
            continue   # MISP marks this attribute as not suitable for detection
        val = str(a.get("value") or "")
        if "|" in typ:
            left, _, right = val.partition("|")
            val = left if typ in ("ip-src|port", "ip-dst|port", "domain|ip") else right
        t = MISP_TYPES[typ]
        if t == "ip" and "/" in val:
            t = "cidr"
        tags = ev_tags + [x.get("name") for x in a.get("Tag") or [] if isinstance(x, dict)]
        desc = " · ".join(x for x in (str(ev.get("info") or ""), str(a.get("category") or ""), str(a.get("comment") or "")) if x)
        it = {"type": t, "value": val, "severity": sev, "tags": [str(x) for x in tags if x][:20], "description": desc[:2000],
              "external_id": (f"misp:{a.get('uuid')}" if a.get("uuid") else None)}
        items.append(it)
    return items, errors


def parse_misp(text: str) -> tuple[list[dict], list[str]]:
    """MISP JSON: an event export ({"Event": ...}), a list of events, or restSearch output ({"response": {"Attribute": [...]}})."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        return [], [f"not valid JSON: {e}"]
    events = []
    if isinstance(doc, dict) and isinstance(doc.get("response"), dict) and "Attribute" in doc["response"]:
        return misp_attributes(doc["response"]["Attribute"])
    if isinstance(doc, dict) and isinstance(doc.get("response"), list):
        events = [e.get("Event", e) for e in doc["response"] if isinstance(e, dict)]
    elif isinstance(doc, dict) and "Event" in doc:
        events = [doc["Event"]]
    elif isinstance(doc, list):
        events = [e.get("Event", e) for e in doc if isinstance(e, dict)]
    if not events:
        return [], ["no MISP event or attribute list found"]
    items, errors = [], []
    for ev in events:
        attrs = list(ev.get("Attribute") or [])
        for o in ev.get("Object") or []:
            attrs += o.get("Attribute") or []
        i, e = misp_attributes(attrs, ev)
        items += i
        errors += e
    return items, errors


def parse(fmt: str, text: str):
    if fmt == "misp":
        return parse_misp(text)
    if fmt == "text":
        return parse_text(text)
    if fmt == "csv":
        return parse_csv(text)
    if fmt == "stix":
        return parse_stix(text)
    raise IndicatorError("format must be text, csv, stix or misp")


# ---- candidate extraction from events (what could match an indicator)
_IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RX = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")
_URL_RX = re.compile(r"https?://[^\s\"'<>]{1,2000}", re.IGNORECASE)
_DOM_RX = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
DOMAIN_KEYS = ("query", "host", "server_name", "hostname", "domain", "rrname", "sni")


def candidates(ev: dict) -> list[tuple[str, str, str]]:
    """(type, normalized value, field) tuples worth looking up for one event."""
    out = set()
    for f in ("src_ip", "dst_ip"):
        v = ev.get(f)
        if v:
            try:
                out.add(("ip", str(ipaddress.ip_address(v)), f))
            except ValueError:
                pass
    msg = ev.get("message") or ""
    raw = ev.get("raw") or {}
    raw_s = json.dumps(raw, default=str)[:20000] if raw else ""
    for f, text in (("message", msg), ("raw", raw_s)):
        for u in _URL_RX.findall(text):
            try:
                out.add(("url", normalize("url", u.rstrip(".,);")), f))
            except IndicatorError:
                pass
        for h in _HASH_RX.findall(text):
            out.add(({32: "md5", 40: "sha1", 64: "sha256"}[len(h)], h.lower(), f))
    if ev.get("host"):
        d = str(ev["host"]).lower().rstrip(".")
        if DOMAIN_RX.match(d):
            out.add(("domain", d, "host"))
    def walk(o, depth=0):
        if depth > 4:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and k.lower() in DOMAIN_KEYS:
                    d = v.lower().rstrip(".")
                    if DOMAIN_RX.match(d):
                        out.add(("domain", d, "raw"))
                elif isinstance(v, dict | list):
                    walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o[:50]:
                walk(v, depth + 1)
    walk(raw)
    for d in _DOM_RX.findall(msg):
        d = d.lower()
        if not d.replace(".", "").isdigit() and DOMAIN_RX.match(d):
            out.add(("domain", d, "message"))
    return sorted(out)
