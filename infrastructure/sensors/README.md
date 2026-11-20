# Sensors profile

`docker compose --profile sensors up -d` runs Suricata and Zeek on the host interface `SENSOR_INTERFACE`
(default `eth0`, set it in `.env`) and ships their JSON logs into the SOC ingest API.

1. In **Defense Center → Log sources**, register one source of type *Suricata EVE* and one of type *Zeek*.
   Each registration downloads a shipper config file once (the ingest key is shown nowhere else).
2. Save them here as `suricata.env` and `zeek.env`. Both are ignored by git: they contain ingest keys.
3. If the downloaded `CR_INGEST_URL` points at a host name the shipper container cannot resolve, change it to
   `http://frontend:8080/api/v1/soc/ingest` (the shipper sits on the stack network).
4. Start the profile. Events appear in SIEM & Log Analysis; rules raise alerts as usual.

Sensors only see traffic on the chosen host interface. Lab bridges are internal, so to watch a lab network point
`SENSOR_INTERFACE` at that lab's bridge (`docker network inspect cr-<runtime>-<subnet>` → `com.docker.network.bridge.name`).


## Sensors inside labs (v1.2)

Lab Manager → lab detail → **Sensor jaringan** starts Zeek and/or Suricata on the lab's own isolated bridges, no
configuration needed. The lab worker collects their JSON logs every 10 s into one log source per sensor
("Lab #N … · zeek · <network>"), so rules, threat intel and the purple-team report use real packet telemetry.
Sensor containers use the host network namespace only to open the lab bridge; they drop all capabilities except
packet capture, run with no-new-privileges and keep logs on tmpfs. They are removed when the lab stops or is destroyed.
Images: `CR_SENSOR_ZEEK_IMAGE` (default zeek/zeek:7.0.5), `CR_SENSOR_SURICATA_IMAGE` (default jasonish/suricata:7.0.8).
Suricata loads a small platform ruleset (`CR-LAB …` signatures, sid 9100001-9100007); build a derived image to add ET Open.

## Wazuh

A Wazuh manager is too heavy to start per lab (several GB, its own indexer) and lab images carry no Wazuh agent,
so Wazuh is integrated from an existing manager instead:

1. Defense Center → Log sources → register a source of type *Wazuh* and copy its ingest key.
2. Copy `wazuh/custom-cyberrange` to `/var/ossec/integrations/` on the manager (owner root:wazuh, mode 750).
3. Add `wazuh/ossec-integration.xml` to `ossec.conf` with your URL and key, then restart the manager.

Every alert at or above the configured level is posted to `/api/v1/soc/ingest` and normalised by the Wazuh parser.
