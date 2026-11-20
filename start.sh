#!/usr/bin/env bash
# CYBER RANGE launcher for Linux/macOS: creates .env with random secrets on first run (values never printed),
# starts the stack with Docker Compose v2, waits until it is ready.
set -euo pipefail
cd "$(dirname "$0")"
docker version >/dev/null 2>&1 || { echo "GAGAL: Docker tidak berjalan. Jalankan Docker lalu coba lagi."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "GAGAL: 'docker compose' (Compose v2) tidak tersedia."; exit 1; }
first_run=0; [ -f .env ] || first_run=1
./scripts/init-env.sh
# Same as start.ps1: on first run, move host ports another program already listens on (e.g. a local MySQL on 3306).
busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
if [ "$first_run" = 1 ]; then
  for pair in FRONTEND_PORT:8080 MYSQL_HOST_PORT:3306 REDIS_HOST_PORT:6379; do
    key=${pair%%:*}; def=${pair##*:}
    cur=$(grep -E "^${key}=" .env | cut -d= -f2); cur=${cur:-$def}
    if busy "$cur"; then
      n=$((cur + 10000)); while busy "$n"; do n=$((n + 1)); done
      if grep -qE "^${key}=" .env; then sed -i.bak "s|^${key}=.*|${key}=${n}|" .env; else echo "${key}=${n}" >> .env; fi
      rm -f .env.bak; echo "  port ${cur} sudah dipakai aplikasi lain, ${key} dipindah ke ${n}"
    fi
  done
fi
docker compose up -d --build
echo "Membangun image lab kantor (domain controller, portal, workstation)..."
docker compose --profile lab-images build lab-office || echo "PERINGATAN: image lab kantor gagal dibangun; template 'Kantor dengan Active Directory' belum bisa dipakai."
port=$(grep -E '^FRONTEND_PORT=' .env | cut -d= -f2); port=${port:-8080}
echo "Menunggu aplikasi siap..."
for _ in $(seq 120); do
  curl -fsS "http://localhost:${port}/api/v1/health/ready" >/dev/null 2>&1 && { ok=1; break; }; sleep 5
done
[ "${ok:-}" = 1 ] || { echo "GAGAL: belum siap setelah 10 menit. Lihat: docker compose logs backend"; exit 1; }
echo "SIAP: http://localhost:${port}"
if grep -qE "^CR_LOCAL_ACCESS_TOKEN=.+" .env; then
  echo "Token akses lokal aktif: buka sekali http://localhost:${port}/#cr-token=<nilai CR_LOCAL_ACCESS_TOKEN di file .env>"
fi
echo "Buka alamat di atas di browser komputer ini. Tidak ada login: edisi lokal untuk satu operator."
