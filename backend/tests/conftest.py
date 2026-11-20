"""Shared test setup. Unit tests need no services; tests marked `integration` need the MySQL test database.

Run inside the backend container:   docker compose exec backend pytest -q
Integration tests use CR_TEST_MYSQL_DATABASE (default cyber_range_test, created by infrastructure/mysql/init).
"""
import os

os.environ.setdefault("CR_JWT_SECRET", "test-secret-test-secret-test-secret-0123")
os.environ.setdefault("CR_MYSQL_PASSWORD", os.environ.get("CR_MYSQL_PASSWORD", "x"))
if os.environ.get("CR_TEST_MYSQL_DATABASE"):
    os.environ["CR_MYSQL_DATABASE"] = os.environ["CR_TEST_MYSQL_DATABASE"]
