#!/usr/bin/env bash
# Restore a backup made by scripts/backup.sh. DESTRUCTIVE: replaces the database and the object storage contents.
# Usage: scripts/restore.sh <backup_dir> --yes [--skip-storage]
# Steps: verify SHA256SUMS -> stop workers -> drop+recreate DB from dump -> replace storage -> migrate to head ->
#        restart workers -> record the restore. .env is never restored automatically (copy env.secret by hand if needed).
set -euo pipefail
cd "$(dirname "$0")/.."
DIR="${1:?backup directory required}"; shift || true
YES=0; SKIP_STORAGE=0
for a in "$@"; do case "$a" in --yes) YES=1;; --skip-storage) SKIP_STORAGE=1;; *) echo "unknown option $a"; exit 2;; esac; done
[ "$YES" = 1 ] || { echo "refusing to restore without --yes (this overwrites the database and stored files)"; exit 2; }
[ -f "$DIR/manifest.json" ] || { echo "not a backup directory: $DIR"; exit 2; }
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; LABEL="$(basename "$DIR")"
dc() { docker compose "$@"; }

echo "[1/6] Verifying checksums"
( cd "$DIR" && sha256sum -c SHA256SUMS )
echo "[2/6] Stopping workers"
dc stop worker beat lab-worker >/dev/null 2>&1 || true
echo "[3/6] Restoring MySQL (drop and recreate database)"
dc exec -T mysql sh -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`; CREATE DATABASE \`$MYSQL_DATABASE\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci; GRANT ALL ON \`$MYSQL_DATABASE\`.* TO \"$MYSQL_USER\"@\"%\";"' 2>/dev/null
gunzip -c "$DIR/mysql.sql.gz" | dc exec -T mysql sh -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD"' 2>/dev/null
if [ "$SKIP_STORAGE" = 0 ]; then
  echo "[4/6] Restoring object storage"
  dc exec -T backend sh -c 'find /var/lib/cyber-range/storage -mindepth 1 -delete && tar -C /var/lib/cyber-range/storage -xzf -' < "$DIR/storage.tar.gz"
else echo "[4/6] Object storage skipped"; fi
echo "[5/6] Migrating to head (no-op when the backup is current)"
dc exec -T backend alembic upgrade head
dc start worker beat lab-worker >/dev/null
echo "[6/6] Recording restore"
# the dump predates its own backup record, so re-record the backup we restored from (idempotent), then the restore
dc exec -T backend python -m app.cli record-backup < "$DIR/manifest.json"
REV="$(dc exec -T mysql sh -c 'exec mysql -N -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SELECT version_num FROM alembic_version" "$MYSQL_DATABASE"' 2>/dev/null | tr -d '\r')"
printf '{"label":"%s","kind":"restore","status":"ok","started_at":"%s","finished_at":"%s","schema_revision":"%s","host":"%s","components":[],"note":"restored from %s"}\n' \
  "$LABEL" "$STARTED" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REV" "$(hostname)" "$LABEL" | dc exec -T backend python -m app.cli record-backup
echo "restore complete from $DIR. Check: curl -s localhost:8080/api/v1/health/ready ; Audit Logs -> Verify integrity"
