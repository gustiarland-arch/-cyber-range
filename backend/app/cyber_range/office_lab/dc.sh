#!/bin/sh
# Active Directory domain controller for an isolated lab (Samba AD DC). Provisions a fresh DEMO domain on every start:
# DEMO employees and departments, two file shares, and JSON audit logging of authentication and directory changes.
set -eu
eval "$(python3 /opt/cr/dcenv.py)"     # DOMAIN REALM NETBIOS ADMINPASS (random, never leaves this container)
IP=$(hostname -i | awk '{print $1}')
mkdir -p /var/log/samba /srv/share/umum /srv/share/keuangan

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  samba-tool domain provision --realm="$REALM" --domain="$NETBIOS" --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --adminpass="$ADMINPASS" --host-ip="$IP" --use-rfc2307 \
    --option="log level = 1 auth_json_audit:3 dsdb_json_audit:2 dsdb_group_json_audit:2" \
    --option="log file = /var/log/samba/samba.log" --option="max log size = 0" \
    --option="vfs objects = dfs_samba4" --option="dns forwarder = 127.0.0.1" \
    --option="interfaces = lo $IP" --option="bind interfaces only = yes" >/var/log/samba/provision.log 2>&1
  python3 /opt/cr/dcseed.py
  cat >> /etc/samba/smb.conf <<CONF

[Umum]
	path = /srv/share/umum
	read only = no
	comment = Dokumen umum perusahaan (DEMO)

[Keuangan]
	path = /srv/share/keuangan
	read only = no
	valid users = @"$NETBIOS\\Keuangan"
	comment = Dokumen departemen Keuangan (DEMO)
CONF
  chmod 0777 /srv/share/umum /srv/share/keuangan
fi
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
printf 'search %s\nnameserver 127.0.0.1\n' "$DOMAIN" > /etc/resolv.conf 2>/dev/null || true
exec samba --foreground --no-process-group
