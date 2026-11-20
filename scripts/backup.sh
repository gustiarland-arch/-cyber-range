#!/usr/bin/env bash
# Full CYBER RANGE backup: MySQL (consistent InnoDB snapshot) + object storage (filesystem adapter volume) + manifest.
# Usage: scripts/backup.sh [--out DIR] [--include-env]
#   --include-env  also copies .env (JWT/encryption secrets, DB passwords) with mode 0600. Store such backups offline
#                  and encrypted; without the secrets, existing sessions and encrypted settings cannot be used.
# Writes DIR/<UTC label>/{mysql.sql.gz, storage.tar.gz, manifest.json, SHA256SUMS} and records the run in the database
# so System Health shows backup status. Never prints secrets.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="./storage/backups"; INCLUDE_ENV=0
while [ $# -gt 0 ]; do case "$1" in --out) OUT="$2"; shift 2;; --include-env) INCLUDE_ENV=1; shift;; *) echo "unknown option $1"; exit 2;; esac; done
LABEL="$(date -u +%Y%m%dT%H%M%SZ)"; STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DIR="$OUT/$LABEL"; umask 077; mkdir -p "$DIR"
dc() { docker compose "$@"; }

echo "[1/4] MySQL dump"
dc exec -T mysql sh -c 'exec mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers --set-gtid-purged=OFF --databases "$MYSQL_DATABASE"' 2>/dev/null \
  | gzip > "$DIR/mysql.sql.gz"
gunzip -t "$DIR/mysql.sql.gz"
zcat "$DIR/mysql.sql.gz" | tail -n 1 | grep -q "Dump completed" || { echo "mysqldump did not complete"; exit 1; }
REV="$(dc exec -T mysql sh -c 'exec mysql -N -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SELECT version_num FROM alembic_version" "$MYSQL_DATABASE"' 2>/dev/null | tr -d '\r')"

echo "[2/4] Object storage (artifact_data volume)"
dc exec -T backend tar -C /var/lib/cyber-range/storage -czf - . > "$DIR/storage.tar.gz"
tar -tzf "$DIR/storage.tar.gz" > /dev/null

if [ "$INCLUDE_ENV" = 1 ]; then echo "[3/4] Copying .env (secrets) with mode 0600"; install -m 0600 .env "$DIR/env.secret"; else echo "[3/4] .env not included (use --include-env)"; fi

echo "[4/4] Manifest"
( cd "$DIR" && sha256sum mysql.sql.gz storage.tar.gz $( [ -f env.secret ] && echo env.secret ) > SHA256SUMS )
FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
comp() { printf '{"name":"%s","file":"%s","size":%s,"sha256":"%s"}' "$1" "$2" "$(stat -c %s "$DIR/$2")" "$(sha256sum "$DIR/$2" | cut -d' ' -f1)"; }
COMPS="$(comp mysql mysql.sql.gz),$(comp storage storage.tar.gz)"
[ -f "$DIR/env.secret" ] && COMPS="$COMPS,$(comp env env.secret)"
printf '{"label":"%s","kind":"backup","status":"ok","started_at":"%s","finished_at":"%s","schema_revision":"%s","host":"%s","components":[%s]}\n' \
  "$LABEL" "$STARTED" "$FINISHED" "$REV" "$(hostname)" "$COMPS" > "$DIR/manifest.json"
dc exec -T backend python -m app.cli record-backup < "$DIR/manifest.json"
echo "backup written: $DIR ($(du -sh "$DIR" | cut -f1)), schema $REV"
