#!/bin/sh
# CYBER RANGE Lab Kit: office lab node on an Ubuntu VM (intranet portal or employee workstation), next to a Windows
# Server domain controller. Same scripts as the office lab inside CYBER RANGE (/opt/cr): host agent + role.
# Lab values come from the Vagrantfile (CR_* environment); the seed is generated on your computer (.lab-seed).
set -eu
ROLE="${1:?role portal|ws}"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y --no-install-recommends krb5-user smbclient dnsutils python3 netcat-openbsd >/dev/null
id karyawan >/dev/null 2>&1 || useradd -m -s /bin/bash karyawan
install -d -m 0755 /opt/cr
cp /tmp/cr-office/*.py /opt/cr/
chmod 0644 /opt/cr/*.py
install -d -m 0700 /etc/cr
umask 077
cat > /etc/cr/lab.env <<ENV
CR_LAB_SEED=$CR_LAB_SEED
CR_DOMAIN=$CR_DOMAIN
CR_PEERS=$CR_PEERS
CR_NODE=$CR_NODE
CR_IP=$CR_IP
CR_DC_HOST=$CR_DC_HOST
CR_EVENTS=$CR_EVENTS
ENV
umask 022
REALM=$(echo "$CR_DOMAIN" | tr '[:lower:]' '[:upper:]')
DC=${CR_PEERS#*dc=}; DC=${DC%%,*}
cat > /etc/krb5.conf <<KRB
[libdefaults]
	default_realm = $REALM
	dns_lookup_kdc = false
	dns_lookup_realm = false
	rdns = false
	dns_canonicalize_hostname = false
[realms]
	$REALM = {
		kdc = $DC
		admin_server = $DC
	}
[domain_realm]
	.$CR_DOMAIN = $REALM
	$CR_DOMAIN = $REALM
KRB
grep -q " $CR_DC_HOST.$CR_DOMAIN" /etc/hosts || echo "$DC $CR_DC_HOST.$CR_DOMAIN $CR_DC_HOST" >> /etc/hosts
mkdir -p "$(dirname "$CR_EVENTS")"
touch "$CR_EVENTS" && chmod 0666 "$CR_EVENTS" 2>/dev/null || true
if [ "$ROLE" = "portal" ]; then RUN="/usr/bin/python3 /opt/cr/portal.py"; else RUN="/usr/bin/python3 /opt/cr/bot.py"; fi
for UNIT in agent role; do
  if [ "$UNIT" = agent ]; then CMD="/usr/bin/python3 /opt/cr/agent.py $ROLE"; DESC="host agent"; else CMD="$RUN"; DESC="$ROLE"; fi
  cat > /etc/systemd/system/cr-$UNIT.service <<UNITFILE
[Unit]
Description=CYBER RANGE office lab $DESC
After=network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=/etc/cr/lab.env
ExecStart=$CMD
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNITFILE
done
systemctl daemon-reload
systemctl enable --now cr-agent.service cr-role.service >/dev/null 2>&1
echo "CYBER RANGE office node ready: $CR_NODE ($ROLE), domain $CR_DOMAIN via $CR_DC_HOST ($DC)"
