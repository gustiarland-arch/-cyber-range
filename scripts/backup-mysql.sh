#!/usr/bin/env bash
# Consistent logical backup of the CYBER RANGE MySQL database (InnoDB, single transaction).
# Usage: scripts/backup-mysql.sh [output_dir]   -> writes cyber_range-YYYYmmddTHHMMSSZ.sql.gz + .sha256
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-./storage/backups}"
mkdir -p "$OUT"
FILE="$OUT/cyber_range-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
docker compose exec -T mysql sh -c 'exec mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers --set-gtid-purged=OFF --databases "$MYSQL_DATABASE"' 2>/dev/null | gzip > "$FILE"
sha256sum "$FILE" > "$FILE.sha256"
echo "backup written: $FILE ($(du -h "$FILE" | cut -f1))"
