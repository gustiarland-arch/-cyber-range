#!/usr/bin/env bash
# Restore a backup made by backup-mysql.sh. DESTRUCTIVE: replaces the current database.
# Usage: scripts/restore-mysql.sh <file.sql.gz> --yes
set -euo pipefail
cd "$(dirname "$0")/.."
FILE="${1:?backup file required}"
[ "${2:-}" = "--yes" ] || { echo "refusing to restore without --yes (this overwrites the database)"; exit 2; }
if [ -f "$FILE.sha256" ]; then sha256sum -c "$FILE.sha256"; fi
gunzip -c "$FILE" | docker compose exec -T mysql sh -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD"' 2>/dev/null
echo "restore complete from $FILE"
