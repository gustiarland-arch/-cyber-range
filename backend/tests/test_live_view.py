"""Live 3D view: pure helpers, plus an integration test of /labs/{id}/live and the local token on the test database."""
import os

import pytest

from app.cyber_range.live import UID_STEP, node_state


@pytest.mark.parametrize("raw,state", [("running", "running"), ("exited", "stopped"), ("paused", "stopped"), ("created", "pending"),
                                       ("restarting", "pending"), ("dead", "error"), ("missing", "error"), ("failed", "error"),
                                       (None, "absent"), ("something-new", "pending")])
def test_node_state_mapping(raw, state):
    assert node_state(raw) == state


def test_redteam_uid_step_parsing():
    m = UID_STEP.match("rt12-3-tcp-10.0.0.1-80")
    assert m and (int(m.group(1)), int(m.group(2))) == (12, 3)
    assert UID_STEP.match("audit-5") is None


def _db_available():
    if not os.environ.get("CR_TEST_MYSQL_DATABASE"):
        return False
    try:
        from sqlalchemy import text

        from app.core.database import SessionLocal
        with SessionLocal() as db:
            db.execute(text("select 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


integration = pytest.mark.skipif(not _db_available(), reason="set CR_TEST_MYSQL_DATABASE to a migrated test database")


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app
    return TestClient(app, base_url="http://localhost")


@integration
def test_local_token_required_when_configured(client, monkeypatch):
    from app.core import config
    monkeypatch.setenv("CR_LOCAL_ACCESS_TOKEN", "T" * 32)
    config.get_settings.cache_clear()
    try:
        assert client.post("/api/v1/auth/local").json()["error"]["code"] == "local_token_required"
        assert client.post("/api/v1/auth/local", headers={"X-Local-Token": "X" * 32}).status_code == 403
        assert client.post("/api/v1/auth/local", headers={"X-Local-Token": "T" * 32}).status_code == 200
    finally:
        monkeypatch.delenv("CR_LOCAL_ACCESS_TOKEN")
        config.get_settings.cache_clear()


@integration
def test_live_endpoint_shape_and_bounds(client):
    tok = client.post("/api/v1/auth/local").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    labs = client.get("/api/v1/labs", headers=h).json()["labs"]
    if not labs:
        pytest.skip("no lab in the test database")
    lid = labs[0]["id"]
    assert client.get(f"/api/v1/labs/{lid}/live", params={"minutes": 1}, headers=h).status_code == 422
    assert client.get(f"/api/v1/labs/{lid}/live", params={"minutes": 5000}, headers=h).status_code == 422
    d = client.get(f"/api/v1/labs/{lid}/live", params={"minutes": 60}, headers=h).json()
    assert set(d) >= {"lab", "instance", "topology", "window", "nodes", "traffic", "alerts", "assessments", "lab_events", "access"}
    assert d["window"]["buckets"] == 60
    for n in d["nodes"]:
        assert n["state"] in ("running", "pending", "stopped", "error", "absent")
    for f in d["traffic"]["flows"]:
        assert len(f["buckets"]) == 60 and sum(f["buckets"]) == f["count"]
    assert client.get("/api/v1/labs/999999/live", headers=h).status_code == 404


@integration
def test_detections_fall_inside_their_own_step():
    """Steps are sequential: evidence credited to a step happened after that step started and before the next one began.
    (One threshold alert may legitimately cover several steps, e.g. a port-scan rule fed by two scanning steps.)"""
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from app.core.database import SessionLocal
    from app.redteam.models import Assessment, AssessmentEvent
    from app.redteam.purple import assessment_steps
    with SessionLocal() as db:
        done = db.execute(select(Assessment).where(Assessment.status == "completed")).scalars().all()
        if not done:
            pytest.skip("no completed assessment in the test database")
        for a in done:
            starts = {e.step_index: e.at for e in db.execute(select(AssessmentEvent).where(
                AssessmentEvent.assessment_id == a.id, AssessmentEvent.kind == "step_started")).scalars()}
            order = sorted(starts)
            for s in assessment_steps(db, a):
                for x in s["alerts"]:
                    at = datetime.fromisoformat(x["first_at"].rstrip("Z"))
                    lo = starts[s["step"]] - (timedelta(seconds=5) if s["step"] == order[0] else timedelta(0))
                    nxt = [starts[i] for i in order if i > s["step"]]
                    assert lo <= at and (not nxt or at < nxt[0]), (a.id, s["step"], x["rule"], at)
                    assert x["detected_after_seconds"] >= 0


@integration
def test_live_has_split_and_history_fields(client):
    tok = client.post("/api/v1/auth/local").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    labs = client.get("/api/v1/labs", headers=h).json()["labs"]
    if not labs:
        pytest.skip("no lab in the test database")
    d = client.get(f"/api/v1/labs/{labs[0]['id']}/live", headers=h).json()
    assert set(d["status_history"]) == {"initial", "changes"}
    for a in d["assessments"]:
        assert "isolated_targets" in a and "attacker_subnets" in a
        for s in a["steps"]:
            assert set(s["isolated_targets"]) <= set(s["targets"])
            if s["detection"]:
                assert s["detection"]["verdict"] in ("detected", "other_rule", "missed")


@integration
def test_long_lived_alert_keeps_linking_newest_events(client):
    """Regression (1.8.1): after MAX_LINKS_PER_ALERT events an open alert stopped linking new ones, so later red team
    steps looked undetected. The newest events must stay linked, with the link count still capped."""
    import json
    import uuid

    from sqlalchemy import func, select

    from app.blueteam.models import AlertEvent, SecurityEvent
    from app.blueteam.service import MAX_LINKS_PER_ALERT
    from app.core.database import SessionLocal
    tok = client.post("/api/v1/auth/local").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    src = client.post("/api/v1/soc/sources", json={"name": f"uji-cap-{uuid.uuid4().hex[:6]}", "kind": "json"}, headers=h).json()
    key = next(line.split("=", 1)[1].strip().strip("'\"") for line in src["config"].splitlines() if "KEY" in line.split("=", 1)[0])
    ip = f"10.250.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"
    recs = [{"timestamp": "2026-01-01T00:00:00Z", "event_uid": f"cap-{ip}-{i}", "category": "http", "src_ip": ip, "dst_ip": "10.0.0.1",
             "message": f"GET /?id=1 union select null-- {i}"} for i in range(MAX_LINKS_PER_ALERT + 25)]
    r = client.post("/api/v1/soc/ingest", headers={"X-Ingest-Key": key, "Content-Type": "application/json"}, content=json.dumps({"records": recs}))
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        newest = db.execute(select(SecurityEvent.id).where(SecurityEvent.event_uid == f"cap-{ip}-{MAX_LINKS_PER_ALERT + 24}")).scalar_one()
        alert_ids = [a for (a,) in db.execute(select(AlertEvent.alert_id).where(AlertEvent.event_id == newest))]
        assert alert_ids, "newest event must still be linked to its alert"
        n = db.execute(select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert_ids[0])).scalar()
        assert n <= MAX_LINKS_PER_ALERT
