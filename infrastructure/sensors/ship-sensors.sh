#!/bin/sh
# Ships Suricata EVE and Zeek JSON logs from the shared sensor volume into the SOC ingest API.
# Needs the shipper configs downloaded when the log sources were registered (Defense Center -> Log sources):
#   infrastructure/sensors/suricata.env   (source type: suricata)
#   infrastructure/sensors/zeek.env       (source type: zeek)
# Re-sending lines is safe: ingestion is idempotent.
set -u
pids=""
if [ -f /infra/sensors/suricata.env ]; then
  python3 /infra/ship-logs.py --config /infra/sensors/suricata.env --follow /logs/eve.json &
  pids="$pids $!"
else
  echo "suricata.env not found: Suricata EVE is not shipped"
fi
if [ -f /infra/sensors/zeek.env ]; then
  for t in ${ZEEK_LOGS:-conn dns http}; do
    python3 /infra/ship-logs.py --config /infra/sensors/zeek.env --follow --dataset "$t" "/logs/zeek/$t.log" &
    pids="$pids $!"
  done
else
  echo "zeek.env not found: Zeek logs are not shipped"
fi
[ -n "$pids" ] || { echo "no shipper config present; see infrastructure/sensors/README.md"; sleep infinity; }
wait
