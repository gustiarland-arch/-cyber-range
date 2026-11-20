#!/usr/bin/env python3
"""Ship sensor logs (Suricata eve.json, Zeek JSON logs, Wazuh alerts.json, syslog) to CYBER RANGE.

Usage:  scripts/ship-logs.py --config cr-shipper-3.env /var/log/suricata/eve.json [--follow] [--dataset conn]
The config file is the one downloaded when the log source was registered. Re-sending lines is safe:
the platform de-duplicates by content, so restarts never create duplicate events.
Stdlib only, so it runs on any sensor host with Python 3.9+.
"""
import argparse
import json
import os
import ssl
import time
import urllib.error
import urllib.request


def load_config(path):
    cfg = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k] = v
    for k in ("CR_INGEST_URL", "CR_INGEST_KEY", "CR_INGEST_KIND"):
        if not cfg.get(k):
            raise SystemExit(f"config is missing {k}")
    return cfg


def send(cfg, lines, dataset, ctx):
    url = f"{cfg['CR_INGEST_URL']}?kind={cfg['CR_INGEST_KIND']}" + (f"&dataset={dataset}" if dataset else "")
    req = urllib.request.Request(url, data="\n".join(lines).encode(), method="POST",
                                 headers={"Content-Type": "text/plain", "X-Ingest-Key": cfg["CR_INGEST_KEY"]})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:  # noqa: S310 - URL comes from the operator's config
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (401, 413, 422):
                raise SystemExit(f"rejected ({e.code}): {e.read()[:300]!r}") from None
        except OSError:
            pass
        time.sleep(2 ** attempt)
    raise SystemExit("platform unreachable after 5 attempts")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("file")
    ap.add_argument("--follow", action="store_true", help="keep reading appended lines (like tail -F)")
    ap.add_argument("--dataset", help="Zeek log type when records lack _path (conn, dns, http, ...)")
    ap.add_argument("--batch", type=int, default=500)
    ap.add_argument("--cafile", help="CA bundle for a private TLS certificate")
    a = ap.parse_args()
    cfg = load_config(a.config)
    ctx = ssl.create_default_context(cafile=a.cafile) if a.cafile else None
    totals = {"accepted": 0, "duplicates": 0, "rejected": 0, "alerts": 0}
    with open(a.file, encoding="utf-8", errors="replace") as f:
        buf = []
        while True:
            line = f.readline()
            if line:
                if line.strip():
                    buf.append(line.rstrip("\n"))
                if len(buf) < a.batch:
                    continue
            if buf:
                r = send(cfg, buf, a.dataset, ctx)
                for k in totals:
                    totals[k] += r.get(k, 0)
                print(json.dumps({**totals, "batch": len(buf)}), flush=True)
                buf = []
            if not line:
                if not a.follow:
                    break
                time.sleep(1)
                if os.stat(a.file).st_ino != os.fstat(f.fileno()).st_ino:  # rotated
                    f.close()
                    f = open(a.file, encoding="utf-8", errors="replace")  # noqa: SIM115
    print("done", json.dumps(totals))


if __name__ == "__main__":
    main()
