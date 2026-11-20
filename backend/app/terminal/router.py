from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.iam.deps import Principal, require
from app.terminal import service

router = APIRouter(tags=["terminal"])
TERM = Depends(require("lab.terminal"))


class OpenIn(BaseModel):
    node_key: str = Field(min_length=1, max_length=64)


@router.post("/terminal/labs/{lab_id}/sessions", status_code=201)
def open_terminal(lab_id: int, body: OpenIn, db: Session = Depends(get_db), p: Principal = TERM):
    return service.open_session(db, p, lab_id, body.node_key)


@router.get("/terminal/labs/{lab_id}/sessions")
def sessions(lab_id: int, db: Session = Depends(get_db), p: Principal = TERM):
    return service.list_for_lab(db, p, lab_id)


@router.post("/terminal/sessions/{session_id}/close")
def close(session_id: int, db: Session = Depends(get_db), p: Principal = TERM):
    return service.close(db, p, session_id)


@router.get("/terminal/sessions/{session_id}/transcript")
def transcript(session_id: int, db: Session = Depends(get_db), p: Principal = TERM):
    s, it = service.transcript(db, p, session_id)
    return StreamingResponse(it, media_type="text/plain; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="terminal-{s.id}-{s.node_key}.log"', "X-Content-Type-Options": "nosniff",
        "X-Transcript-SHA256": s.transcript_sha256 or ""})
