"""Optional GeoIP lookups from a local MaxMind-format database (GeoLite2-City / GeoIP2-City .mmdb).

No database ships with the platform (MaxMind's licence requires each operator to download it with their own free
account). Point CR_GEOIP_DB at the file; without it, lookups return only whether an address is private/lab space.
Nothing is ever sent to an online GeoIP service.
"""
import ipaddress
import os
from functools import lru_cache

_reader = None
_path = None


def db_path() -> str:
    return os.environ.get("CR_GEOIP_DB", "/var/lib/cyber-range/geoip/GeoLite2-City.mmdb")


def reader():
    global _reader, _path
    p = db_path()
    if _reader is not None and _path == p:
        return _reader
    _reader, _path = None, p
    if not os.path.isfile(p):
        return None
    try:
        import maxminddb
        _reader = maxminddb.open_database(p)
    except Exception:  # noqa: BLE001 - a broken file must not break alert views
        _reader = None
    lookup.cache_clear()
    return _reader


def status() -> dict:
    r = reader()
    if not r:
        return {"available": False, "path": db_path()}
    m = r.metadata()
    return {"available": True, "path": db_path(), "database_type": m.database_type, "build_epoch": m.build_epoch}


@lru_cache(maxsize=20000)
def lookup(ip: str) -> dict:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "valid": False}
    out = {"ip": ip, "valid": True, "private": a.is_private or a.is_loopback or a.is_link_local, "country": None, "country_name": None,
           "city": None, "lat": None, "lon": None}
    if out["private"]:
        return out
    r = reader()
    if not r:
        return out
    rec = r.get(ip) or {}
    loc = rec.get("location") or {}
    out.update(country=(rec.get("country") or {}).get("iso_code"), country_name=((rec.get("country") or {}).get("names") or {}).get("en"),
               city=((rec.get("city") or {}).get("names") or {}).get("en"), lat=loc.get("latitude"), lon=loc.get("longitude"))
    return out
