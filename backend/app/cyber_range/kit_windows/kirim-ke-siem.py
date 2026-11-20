#!/usr/bin/env python3
"""CYBER RANGE Lab Kit: ship the lab's telemetry (telemetry/*.jsonl) to the SIEM of your CYBER RANGE app.

1. In CYBER RANGE: SIEM & Analisis Log -> Sumber log -> tambah sumber jenis "json". Save the configuration file the app
   gives you as cr-shipper.env in this kit folder (it holds the ingest key; this kit never contains one).
2. Run: python3 kirim-ke-siem.py   (Ctrl+C to stop). It sends new lines every 15 seconds and remembers what it sent
   in telemetry/.terkirim.json, so it can be stopped and started again.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.join(HERE, "cr-shipper.env")
TEL = os.path.join(HERE, "telemetry")
STATE = os.path.join(TEL, ".terkirim.json")
BATCH = 2000


def config() -> dict:
    if not os.path.exists(CONF):
        sys.exit("cr-shipper.env tidak ditemukan. Buat sumber log jenis json di SIEM, lalu simpan file konfigurasinya di folder ini.")
    conf = {}
    for line in open(CONF, encoding="utf-8"):
        k, _, v = line.strip().partition("=")
        if k and not k.startswith("#"):
            conf[k] = v
    if conf.get("CR_INGEST_KIND") != "json":
        sys.exit("Sumber log harus berjenis json (CR_INGEST_KIND=json).")
    if not conf.get("CR_INGEST_URL", "").startswith(("http://", "https://")) or not conf.get("CR_INGEST_KEY"):
        sys.exit("cr-shipper.env tidak lengkap.")
    return conf


def send(conf: dict, lines: list[bytes]) -> None:
    req = urllib.request.Request(conf["CR_INGEST_URL"], data=b"\n".join(lines) + b"\n", method="POST",  # noqa: S310 (URL from your own config)
                                 headers={"Content-Type": "text/plain", "X-Ingest-Key": conf["CR_INGEST_KEY"]})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
        r.read()


def main() -> None:
    conf = config()
    os.makedirs(TEL, exist_ok=True)
    try:
        sent = json.load(open(STATE))
    except (OSError, ValueError):
        sent = {}
    print(f"Mengirim telemetri dari {TEL} ke {conf['CR_INGEST_URL']} (Ctrl+C untuk berhenti)")
    while True:
        for name in sorted(os.listdir(TEL)):
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(TEL, name)
            off = int(sent.get(name, 0))
            if os.path.getsize(path) < off:      # the file was recreated (vagrant destroy / up)
                off = 0
            with open(path, "rb") as f:
                f.seek(off)
                chunk = f.read(8_000_000)
            end = chunk.rfind(b"\n")
            if end < 0:
                continue
            lines = [ln for ln in chunk[:end].split(b"\n") if ln.strip()]
            try:
                for i in range(0, len(lines), BATCH):
                    send(conf, lines[i:i + BATCH])
            except (urllib.error.URLError, OSError) as e:
                print(f"{name}: gagal mengirim ({e}). Dicoba lagi nanti.")
                continue
            sent[name] = off + end + 1
            json.dump(sent, open(STATE, "w"))
            if lines:
                print(f"{time.strftime('%H:%M:%S')} {name}: {len(lines)} event terkirim")
        time.sleep(15)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
