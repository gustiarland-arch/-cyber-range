#!/bin/sh
# API container entrypoint: migrate, seed the catalog and the local operator, then serve.
set -e
alembic upgrade head
python -m app.cli seed
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*' --no-server-header
