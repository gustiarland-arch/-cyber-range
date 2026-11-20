#!/usr/bin/env bash
# Fill empty secret values in .env with strong random values. Prints only key names, never values.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
gen() { LC_ALL=C tr -dc "A-Za-z0-9" </dev/urandom | head -c "$(( $1 + $1 / 3 ))"; }
for key in MYSQL_PASSWORD MYSQL_ROOT_PASSWORD CR_JWT_SECRET REDIS_PASSWORD; do
  if grep -qE "^${key}=$" .env; then sed -i.bak "s|^${key}=$|${key}=$(gen 36)|" .env && echo "generated ${key}"
  elif ! grep -qE "^${key}=" .env; then echo "${key}=$(gen 36)" >> .env && echo "generated ${key} (added to an older .env)"; fi
done
if [ -S /var/run/docker.sock ]; then
  gid=$(stat -c %g /var/run/docker.sock)
  if grep -qE "^DOCKER_GID=" .env; then sed -i.bak "s|^DOCKER_GID=.*|DOCKER_GID=${gid}|" .env; else echo "DOCKER_GID=${gid}" >> .env; fi
  echo "set DOCKER_GID (lab worker access to the Docker engine)"
fi
if [ "${1:-}" = "--with-local-token" ]; then
  if grep -qE "^CR_LOCAL_ACCESS_TOKEN=$" .env; then sed -i.bak "s|^CR_LOCAL_ACCESS_TOKEN=$|CR_LOCAL_ACCESS_TOKEN=$(gen 36)|" .env && echo "generated CR_LOCAL_ACCESS_TOKEN"
  elif ! grep -qE "^CR_LOCAL_ACCESS_TOKEN=" .env; then echo "CR_LOCAL_ACCESS_TOKEN=$(gen 36)" >> .env && echo "generated CR_LOCAL_ACCESS_TOKEN"; fi
fi
rm -f .env.bak
chmod 600 .env
