# syntax=docker/dockerfile:1
# CYBER RANGE office lab image: one image, three roles chosen by the command in the image allowlist:
#   /opt/cr/start dc      Active Directory domain controller (Samba AD DC) with DEMO employees and file shares
#   /opt/cr/start portal  intranet portal (login against the domain controller)
#   /opt/cr/start ws      employee workstation with a simulated employee (logins, file shares, portal, DNS)
# Every role runs /opt/cr/agent.py, which writes host telemetry (processes, logins, file changes, listening ports, domain
# authentication) as JSON lines to /var/log/cr/events.jsonl; the lab worker ships them to the SIEM.
# Built locally by start.bat/start.sh (docker compose --profile lab-images build). Lab use only, never on a real network.
FROM ubuntu:24.04
RUN --mount=type=secret,id=extra_ca,required=false \
    set -e; sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources; \
    CA=""; if [ -f /run/secrets/extra_ca ]; then cp /run/secrets/extra_ca /tmp/extra_ca.crt; chmod 644 /tmp/extra_ca.crt; \
      CA="-o Acquire::https::CAInfo=/tmp/extra_ca.crt"; fi; \
    apt-get $CA update -qq; \
    DEBIAN_FRONTEND=noninteractive apt-get $CA install -y -qq --no-install-recommends \
      ca-certificates samba samba-ad-dc samba-ad-provision winbind krb5-user smbclient ldb-tools ldap-utils dnsutils \
      python3 iproute2 iputils-ping procps netcat-openbsd wget curl >/dev/null; \
    rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf /tmp/extra_ca.crt; \
    useradd -m -s /bin/bash karyawan
# Scripts live in backend/app/cyber_range/office_lab (the Lab Kit ships the same files to VMs); compose passes them
# as the build context "cr".
COPY --from=cr . /opt/cr/
RUN chmod 0755 /opt/cr/start /opt/cr/dc.sh && mkdir -p /var/log/cr
CMD ["/opt/cr/start", "ws"]
