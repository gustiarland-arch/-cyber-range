"""Terminal broker: issues one-time tickets for a specific running lab container after server-side checks.

The browser never talks to Docker. It opens a WebSocket to the terminal gateway (separate service, reachable only
through the reverse proxy) and presents the ticket. The gateway re-validates the session and the container labels
before attaching an interactive shell inside that lab container. Host shells are never offered."""
import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.context import current_context
from app.core.database import utcnow
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.redis_client import get_redis
from app.cyber_range import service as labs
from app.cyber_range.engine.safety import kill_switch_engaged
from app.terminal.models import OPEN, TerminalSession

TICKET_TTL = 60          # seconds a ticket may wait before the WebSocket presents it
MAX_OPEN_PER_USER = 3
MAX_SECONDS = 30 * 60    # hard session limit, enforced by the gateway
IDLE_SECONDS = 10 * 60


def ticket_key(ticket_hash: str) -> str:
    return f"term:ticket:{ticket_hash}"


def _hash(ticket: str) -> str:
    return hashlib.sha256(ticket.encode()).hexdigest()


def out(s: TerminalSession, users: dict | None = None) -> dict:
    return {"id": s.id, "lab_id": s.lab_id, "node_key": s.node_key, "container": s.container_name, "status": s.status,
            "user": (users or {}).get(s.user_id), "issued_at": s.issued_at, "started_at": s.started_at, "ended_at": s.ended_at,
            "end_reason": s.end_reason, "bytes_in": s.bytes_in, "bytes_out": s.bytes_out,
            "transcript": bool(s.transcript_key), "transcript_sha256": s.transcript_sha256}


def expire_stale(db: Session) -> None:
    cutoff = utcnow() - timedelta(seconds=TICKET_TTL + 5)
    for s in db.scalars(select(TerminalSession).where(TerminalSession.status == "issued", TerminalSession.issued_at < cutoff)):
        s.status, s.ended_at, s.end_reason = "expired", utcnow(), "ticket not used"


def open_session(db: Session, p, lab_id: int, node_key: str) -> dict:
    lab = labs.get_lab(db, p, lab_id, operate=True)
    if kill_switch_engaged(db):
        raise Conflict("The lab kill switch is engaged", code="kill_switch")
    inst = labs.current_instance(db, lab)
    if inst is None or inst.status != "running":
        raise Conflict("The lab is not running", code="lab_not_running")
    c = next((c for c in inst.containers if c.node_key == node_key), None)
    if c is None or not c.docker_id:
        raise NotFound("No container for this node in the running lab")
    if c.status != "running":
        raise Conflict(f"The container is {c.status}", code="container_not_running")
    expire_stale(db)
    n_open = db.execute(select(func.count()).select_from(TerminalSession)
                        .where(TerminalSession.user_id == p.id, TerminalSession.status.in_(OPEN))).scalar_one()
    if n_open >= MAX_OPEN_PER_USER:
        raise AppError(f"At most {MAX_OPEN_PER_USER} terminal sessions may be open at once", code="quota_exceeded", status_code=429)
    ticket = secrets.token_urlsafe(32)
    s = TerminalSession(user_id=p.id, lab_id=lab.id, instance_id=inst.id, node_key=node_key, container_name=c.name,
                        docker_id=c.docker_id, ticket_hash=_hash(ticket), client_ip=current_context().ip)
    db.add(s)
    db.flush()
    record(db, "lab.terminal.open", actor=p, resource_type="lab", resource_id=lab.id,
           details={"session_id": s.id, "node": node_key, "container": c.name})
    db.commit()
    get_redis().set(ticket_key(s.ticket_hash), str(s.id), ex=TICKET_TTL)
    return {**out(s), "ticket": ticket, "ws_path": "/terminal/ws", "expires_in": TICKET_TTL,
            "limits": {"max_seconds": MAX_SECONDS, "idle_seconds": IDLE_SECONDS}}


def _visible(db: Session, p, session_id: int) -> TerminalSession:
    s = db.get(TerminalSession, session_id)
    if s is None or not (s.user_id == p.id or p.has("lab.manage")):
        raise NotFound("Terminal session not found")
    return s


def close(db: Session, p, session_id: int) -> dict:
    s = _visible(db, p, session_id)
    if s.status in OPEN:
        s.status, s.ended_at, s.end_reason, s.closed_by = "closed", utcnow(), "closed by user" if s.user_id == p.id else "closed by lab manager", p.id
        record(db, "lab.terminal.close", actor=p, resource_type="lab", resource_id=s.lab_id, details={"session_id": s.id})
        db.commit()
        get_redis().delete(ticket_key(s.ticket_hash))
    return out(s)


def list_for_lab(db: Session, p, lab_id: int) -> list[dict]:
    lab = labs.get_lab(db, p, lab_id)
    expire_stale(db)
    db.commit()
    q = select(TerminalSession).where(TerminalSession.lab_id == lab.id).order_by(TerminalSession.id.desc()).limit(50)
    if not p.has("lab.manage"):
        q = q.where(TerminalSession.user_id == p.id)
    rows = list(db.scalars(q))
    from app.iam.models import User
    users = dict(db.execute(select(User.id, User.username).where(User.id.in_({r.user_id for r in rows} or {0}))).all())
    return [out(r, users) for r in rows]


def transcript(db: Session, p, session_id: int):
    s = _visible(db, p, session_id)
    if not s.transcript_key:
        raise NotFound("No transcript stored for this session")
    if s.user_id != p.id and not p.has("lab.manage"):
        raise Forbidden("Not allowed")
    record(db, "lab.terminal.transcript", actor=p, resource_type="lab", resource_id=s.lab_id, details={"session_id": s.id})
    db.commit()
    from app.core.storage import get_storage
    return s, get_storage().open_iter(s.transcript_key)
