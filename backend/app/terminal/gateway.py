"""Isolated terminal gateway (separate service: `uvicorn app.terminal.gateway:app`).

Reachable only through the reverse proxy at /terminal/ws. It is the only component that attaches interactive
shells, and only inside lab containers:

1. the browser opens the WebSocket and sends {"ticket": ...} as its first message (never in the URL);
2. the ticket is consumed from Redis (one-time, 60 s) and mapped to an issued TerminalSession row;
3. the container is re-inspected: it must carry the cyber-range labels of that exact lab, instance and node,
   and be running; anything else is refused (no host shell, no cross-lab access);
4. while the shell runs, the session row, the lab kill switch and the lab state are re-checked every few seconds;
   idle (10 min) and total (30 min) limits apply; closing from the UI or engaging the kill switch ends it;
5. a transcript (capped) goes to object storage with its SHA-256; open/close are written to the audit log.
"""
import asyncio
import contextlib
import hashlib
import io
import json
import time
from urllib.parse import urlsplit

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from app import models  # noqa: F401  (register mappers)
from app.audit.service import record
from app.core.database import SessionLocal, utcnow
from app.core.logging import configure_logging, log
from app.core.redis_client import get_redis
from app.cyber_range.engine.safety import kill_switch_engaged
from app.cyber_range.models import LabInstance
from app.terminal.models import TerminalSession
from app.terminal.service import IDLE_SECONDS, MAX_SECONDS, TICKET_TTL, ticket_key

TRANSCRIPT_CAP = 2 * 1024 * 1024
CHECK_EVERY = 3.0
SHELL = ["/bin/sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi"]

configure_logging(False)
app = FastAPI(title="CYBER RANGE terminal gateway", docs_url=None, redoc_url=None, openapi_url=None)
_docker = None


def docker_api():
    global _docker
    if _docker is None:
        import docker
        _docker = docker.from_env(timeout=30).api
    return _docker


@app.get("/terminal/healthz")
def healthz():
    return {"status": "ok"}


def _size(value, default: int, lo: int, hi: int) -> int:
    """Terminal dimension from client JSON: any non-integer falls back to the default, then it is clamped."""
    try:
        v = int(value) if value not in (None, "") and not isinstance(value, bool) else default
    except (TypeError, ValueError):
        v = default
    return max(lo, min(v, hi))


def _same_origin(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin")
    if not origin:
        return True  # non-browser client; the one-time ticket is still required
    host = ws.headers.get("x-forwarded-host") or ws.headers.get("host") or ""
    return urlsplit(origin).netloc == host


def _end(sid: int, status: str, reason: str, *, bytes_in=0, bytes_out=0, transcript: bytes | None = None, outcome="success") -> None:
    db = SessionLocal()
    try:
        s = db.get(TerminalSession, sid)
        if s is None:
            return
        if transcript:
            from app.core.storage import get_storage
            key = f"terminal/{s.lab_id}/{s.id}.log"
            get_storage().put(key, io.BytesIO(transcript), len(transcript))
            s.transcript_key, s.transcript_sha256 = key, hashlib.sha256(transcript).hexdigest()
        if s.status in ("issued", "active"):
            s.status, s.ended_at, s.end_reason = status, utcnow(), reason[:64]
        s.bytes_in, s.bytes_out = bytes_in, bytes_out
        user = type("A", (), {"id": s.user_id, "username": None})()
        from app.iam.models import User
        u = db.get(User, s.user_id)
        record(db, "lab.terminal.end", outcome=outcome, actor=user, actor_label=u.username if u else "unknown", resource_type="lab",
               resource_id=s.lab_id, details={"session_id": s.id, "reason": reason, "bytes_in": bytes_in, "bytes_out": bytes_out,
                                              "transcript_sha256": s.transcript_sha256})
        db.commit()
    except Exception:
        db.rollback()
        log.exception("terminal_end_failed", session_id=sid)
    finally:
        db.close()


def _claim(ticket: str) -> tuple[TerminalSession | None, str]:
    th = hashlib.sha256(ticket.encode()).hexdigest()
    sid = get_redis().getdel(ticket_key(th))
    if not sid:
        return None, "invalid or expired ticket"
    db = SessionLocal()
    try:
        s = db.get(TerminalSession, int(sid))
        if s is None or s.ticket_hash != th or s.status != "issued":
            return None, "session is not open"
        if (utcnow() - s.issued_at).total_seconds() > TICKET_TTL + 5:
            s.status, s.ended_at, s.end_reason = "expired", utcnow(), "ticket expired"
            db.commit()
            return None, "ticket expired"
        if kill_switch_engaged(db):
            s.status, s.ended_at, s.end_reason = "denied", utcnow(), "kill switch engaged"
            db.commit()
            return None, "the lab kill switch is engaged"
        inst = db.get(LabInstance, s.instance_id)
        if inst is None or inst.status != "running":
            s.status, s.ended_at, s.end_reason = "denied", utcnow(), "lab not running"
            db.commit()
            return None, "the lab is not running"
        # re-inspect the container: it must be the labelled container of this lab, instance and node
        try:
            info = docker_api().inspect_container(s.docker_id)
        except Exception:
            info = None
        labels = ((info or {}).get("Config") or {}).get("Labels") or {}
        ok = (info is not None and labels.get("cyber-range.managed") == "true" and labels.get("cyber-range.lab") == str(s.lab_id)
              and labels.get("cyber-range.instance") == inst.runtime_id and labels.get("cyber-range.node") == s.node_key
              and (info.get("State") or {}).get("Running"))
        if not ok:
            s.status, s.ended_at, s.end_reason = "denied", utcnow(), "container check failed"
            db.commit()
            return None, "the container is not an active container of this lab"
        s.status, s.started_at = "active", utcnow()
        db.commit()
        db.refresh(s)
        db.expunge(s)
        return s, ""
    finally:
        db.close()


def _still_allowed(sid: int, runtime_status_of: int) -> str | None:
    db = SessionLocal()
    try:
        s = db.get(TerminalSession, sid)
        if s is None or s.status != "active":
            return (s.end_reason if s else None) or "session closed"
        if kill_switch_engaged(db):
            return "kill switch engaged"
        inst = db.get(LabInstance, runtime_status_of)
        if inst is None or inst.status != "running":
            return "lab stopped"
        return None
    finally:
        db.close()


@app.websocket("/terminal/ws")
async def terminal(ws: WebSocket):
    if not _same_origin(ws):
        await ws.close(code=4403)
        return
    await ws.accept()
    loop = asyncio.get_running_loop()
    try:
        first = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=10))
        ticket = str(first.get("ticket") or "")[:128]
        # validated before the one-time ticket is consumed, so a malformed size never leaves an orphaned session
        cols, rows = _size(first.get("cols"), 100, 20, 400), _size(first.get("rows"), 30, 5, 200)
    except Exception:
        await ws.close(code=4400, reason="ticket required")
        return
    s, why = await loop.run_in_executor(None, _claim, ticket)
    if s is None:
        await ws.send_text(json.dumps({"t": "error", "message": why}))
        await ws.close(code=4403, reason=why[:120])
        return

    api = docker_api()
    try:
        ex = await loop.run_in_executor(None, lambda: api.exec_create(
            s.docker_id, ["timeout", "-s", "KILL", str(MAX_SECONDS + 30), *SHELL], stdin=True, tty=True, privileged=False,
            environment={"TERM": "xterm-256color", "COLUMNS": str(cols), "LINES": str(rows)}))
        sock = await loop.run_in_executor(None, lambda: api.exec_start(ex["Id"], socket=True, tty=True))
        raw = getattr(sock, "_sock", sock)
        raw.setblocking(False)
        try:
            await loop.run_in_executor(None, lambda: api.exec_resize(ex["Id"], height=rows, width=cols))
        except Exception as e:  # noqa: BLE001  (resize is cosmetic)
            log.debug("terminal_resize_failed", error=str(e)[:120])
    except Exception as e:  # noqa: BLE001
        log.warning("terminal_exec_failed", session_id=s.id, error=str(e)[:200])
        await ws.send_text(json.dumps({"t": "error", "message": "could not start a shell in this container"}))
        await ws.close(code=1011)
        await loop.run_in_executor(None, lambda: _end(s.id, "closed", "exec failed", outcome="failure"))
        return

    await ws.send_text(json.dumps({"t": "ready", "session_id": s.id, "container": s.container_name, "node": s.node_key,
                                   "limits": {"max_seconds": MAX_SECONDS, "idle_seconds": IDLE_SECONDS}}))
    started, last_input = time.monotonic(), time.monotonic()
    transcript, stats = bytearray(), {"in": 0, "out": 0}
    reason = "client disconnected"

    def keep(prefix: bytes, data: bytes) -> None:
        if len(transcript) < TRANSCRIPT_CAP:
            transcript.extend(prefix + data[: TRANSCRIPT_CAP - len(transcript)])

    async def pump_out():
        while True:
            data = await loop.sock_recv(raw, 65536)
            if not data:
                return "shell exited"
            stats["out"] += len(data)
            keep(b"", data)
            await ws.send_bytes(data)

    async def pump_in():
        nonlocal last_input
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                return "client disconnected"
            text = msg.get("text")
            if text is None:
                continue
            try:
                m = json.loads(text)
            except ValueError:
                continue
            if m.get("t") == "i":
                data = str(m.get("d", ""))[:8192].encode()
                stats["in"] += len(data)
                last_input = time.monotonic()
                await loop.sock_sendall(raw, data)
            elif m.get("t") == "r":
                c, r = _size(m.get("c"), 80, 20, 400), _size(m.get("r"), 24, 5, 200)
                try:
                    await loop.run_in_executor(None, lambda c=c, r=r: api.exec_resize(ex["Id"], height=r, width=c))
                except Exception as e:  # noqa: BLE001
                    log.debug("terminal_resize_failed", error=str(e)[:120])

    async def guard():
        while True:
            await asyncio.sleep(CHECK_EVERY)
            if time.monotonic() - started > MAX_SECONDS:
                return "session time limit reached"
            if time.monotonic() - last_input > IDLE_SECONDS:
                return "idle timeout"
            why = await loop.run_in_executor(None, _still_allowed, s.id, s.instance_id)
            if why:
                return why

    tasks = [asyncio.create_task(t()) for t in (pump_out, pump_in, guard)]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            try:
                reason = t.result() or reason
            except WebSocketDisconnect:
                reason = "client disconnected"
            except Exception as e:  # noqa: BLE001
                reason = f"error: {type(e).__name__}"
        if reason in ("shell exited", "client disconnected"):
            # the shell may have died because the lab was stopped or the kill switch engaged: report the real cause
            why = await loop.run_in_executor(None, _still_allowed, s.id, s.instance_id)
            if why and why not in ("session closed",):
                reason = why
    finally:
        with contextlib.suppress(Exception):
            raw.close()
        with contextlib.suppress(Exception):
            await ws.send_text(json.dumps({"t": "closed", "reason": reason}))
            await ws.close()
        await loop.run_in_executor(None, lambda: _end(s.id, "closed", reason, bytes_in=stats["in"], bytes_out=stats["out"],
                                                      transcript=bytes(transcript) or None))
