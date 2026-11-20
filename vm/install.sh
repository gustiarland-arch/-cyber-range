#!/usr/bin/env bash
# Runs inside the VM (as root) on `vagrant up` and `vagrant provision`: installs Docker, copies the app to
# /opt/cyber-range, and starts it. Re-running updates the code and keeps .env (secrets) and all Docker volumes (data).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
SRC=${CR_SRC:-/vagrant-src}
DST=${CR_DST:-/opt/cyber-range}

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Memasang Docker..."
  apt-get -qq update
  apt-get -qq install -y docker.io docker-compose-v2 curl rsync >/dev/null
  systemctl enable --now docker
fi
command -v rsync >/dev/null 2>&1 || apt-get -qq install -y rsync >/dev/null
id vagrant >/dev/null 2>&1 && usermod -aG docker vagrant || true

echo "Menyalin aplikasi ke ${DST}..."
mkdir -p "$DST"
# .env is created inside the VM with its own secrets; a host .env is never copied in.
rsync -a --delete --exclude ".env" --exclude ".env.bak" --exclude "storage/" --exclude "vm/" --exclude ".git/" \
  --exclude "node_modules/" "$SRC/" "$DST/"
mkdir -p "$DST/storage/geoip"
find "$DST" -name "*.sh" -exec chmod +x {} +
cd "$DST"

./scripts/init-env.sh
# Inside the VM the app listens on all VM interfaces so that Vagrant's port forward (bound to the host's 127.0.0.1)
# can reach it. The VM has only the NAT adapter, which other machines cannot reach.
if grep -qE '^FRONTEND_BIND=' .env; then sed -i 's|^FRONTEND_BIND=.*|FRONTEND_BIND=0.0.0.0|' .env; else echo 'FRONTEND_BIND=0.0.0.0' >> .env; fi
sed -i 's|^FRONTEND_PORT=.*|FRONTEND_PORT=8080|' .env

./start.sh
