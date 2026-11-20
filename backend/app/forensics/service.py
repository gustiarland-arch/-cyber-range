"""Evidence intake, hash-chained chain of custody, integrity verification and custody reports."""
import hashlib
import io
import json
import os
import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam.models import AlertEvent, SecurityEvent
from app.blueteam.service import _event_dict
from app.core.database import utcnow
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.storage import get_storage, spool
from app.forensics.models import CustodyEvent, Evidence, EvidenceHash, ForensicCase
from app.governance.service import get_value
from app.iam.models import User
from app.malware.models import FileSample

GENESIS = "0" * 64


def _entry_hash(prev: str, ev: CustodyEvent) -> str:
    body = {"evidence_id": ev.evidence_id, "seq": ev.seq, "action": ev.action, "actor": ev.actor_label, "from": ev.from_custodian,
            "to": ev.to_custodian, "reason": ev.reason, "location": ev.location, "sha256": ev.sha256_observed, "result": ev.result,
            "details": ev.details, "at": ev.at.isoformat()}
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))).encode()).hexdigest()


def custody(db: Session, e: Evidence, action: str, actor, *, reason: str = "", location: str = "", frm: str | None = None, to: str | None = None,
            sha256: str | None = None, result: str | None = None, details: dict | None = None) -> CustodyEvent:
    """Append a custody entry. Caller holds the evidence row lock (SELECT ... FOR UPDATE) so seq/head are consistent."""
    seq = e.custody_seq + 1
    ev = CustodyEvent(evidence_id=e.id, seq=seq, action=action, actor_id=getattr(actor, "id", None), actor_label=getattr(actor, "username", str(actor))[:64],
                      from_custodian=frm, to_custodian=to, reason=reason[:4000], location=location[:255], sha256_observed=sha256, result=result,
                      details=details or {}, at=utcnow(), prev_hash=e.custody_head)
    ev.entry_hash = _entry_hash(e.custody_head, ev)
    db.add(ev)
    e.custody_seq, e.custody_head = seq, ev.entry_hash
    return ev


def verify_chain(db: Session, e: Evidence) -> dict:
    prev, n = GENESIS, 0
    for ev in db.execute(select(CustodyEvent).where(CustodyEvent.evidence_id == e.id).order_by(CustodyEvent.seq)).scalars():
        n += 1
        if ev.seq != n or ev.prev_hash != prev or _entry_hash(prev, ev) != ev.entry_hash:
            return {"valid": False, "entries": n, "broken_at": ev.seq}
        prev = ev.entry_hash
    ok = n == e.custody_seq and prev == e.custody_head
    return {"valid": ok, "entries": n, "broken_at": None if ok else n + 1}


# ------------------------------------------------------------------ cases
def new_case(db: Session, p, *, title: str, description: str, classification: str, incident_id: int | None) -> ForensicCase:
    year = utcnow().year
    n = db.execute(select(func.count()).select_from(ForensicCase).where(ForensicCase.reference.like(f"CASE-{year}-%"))).scalar_one()
    c = ForensicCase(reference=f"CASE-{year}-{n + 1:04d}", title=title, description=description, classification=classification,
                     incident_id=incident_id, lead_id=p.id, created_by=p.id)
    db.add(c)
    db.flush()
    record(db, "forensics.case.create", actor=p, resource_type="forensic_case", resource_id=c.id, details={"reference": c.reference, "incident": incident_id})
    return c


def _next_ref(db, c: ForensicCase) -> str:
    n = db.execute(select(func.count()).select_from(Evidence).where(Evidence.case_id == c.id)).scalar_one()
    return f"{c.reference}/E-{n + 1:03d}"


def _open_case(db, case_id: int) -> ForensicCase:
    c = db.execute(select(ForensicCase).where(ForensicCase.id == case_id).with_for_update()).scalar_one_or_none()
    if not c:
        raise NotFound("Case not found")
    if c.status != "open":
        raise Conflict("The case is closed; reopen it to add evidence", code="case_closed")
    return c


def _create(db, p, c: ForensicCase, *, kind, title, description, source, collected_at, location, filename, size, hashes: dict,
            storage_key, sample_id=None, origin=None) -> Evidence:
    e = Evidence(reference=_next_ref(db, c), case_id=c.id, kind=kind, title=title, description=description, source=source, collected_by=p.id,
                 collected_at=collected_at, filename=filename, size=size, sha256=hashes["sha256"], storage_key=storage_key, sample_id=sample_id,
                 origin=origin or {}, custodian_id=p.id, integrity="verified", last_verified_at=utcnow())
    db.add(e)
    db.flush()
    for algo, val in hashes.items():
        db.add(EvidenceHash(evidence_id=e.id, algorithm=algo, value=val))
    custody(db, e, "collected", p, reason=f"Acquired from {source or 'unspecified source'}", location=location, to=p.username, sha256=hashes["sha256"],
            result="recorded", details={"size": size, "filename": filename, "kind": kind, "collected_at": collected_at.isoformat(), **({"origin": origin} if origin else {})})
    record(db, "forensics.evidence.collect", actor=p, resource_type="evidence", resource_id=e.id,
           details={"reference": e.reference, "sha256": e.sha256, "kind": kind, "size": size})
    return e


def add_file(db: Session, p, case_id: int, fileobj, filename: str, *, kind: str, title: str, description: str, source: str,
             collected_at: datetime | None, location: str) -> Evidence:
    c = _open_case(db, case_id)
    max_bytes = int(get_value(db, "evidence.max_upload_mb")) * 1024 * 1024
    sp = spool(fileobj, max_bytes)
    try:
        key = f"evidence/{c.id}/{uuid.uuid4().hex}.bin"
        get_storage().put(key, sp.file, sp.size)
    finally:
        sp.close()
    name = os.path.basename(filename or "evidence.bin")[:255]
    e = _create(db, p, c, kind=kind, title=title, description=description, source=source, collected_at=(collected_at or utcnow()).replace(tzinfo=None),
                location=location, filename=name, size=sp.size, hashes={"sha256": sp.sha256, "sha1": sp.sha1, "md5": sp.md5}, storage_key=key)
    db.commit()
    return e


def add_sample(db: Session, p, case_id: int, sample_id: int, *, title: str, description: str, location: str) -> Evidence:
    c = _open_case(db, case_id)
    s = db.get(FileSample, sample_id)
    if not s:
        raise NotFound("Sample not found")
    if db.execute(select(Evidence).where(Evidence.case_id == c.id, Evidence.sample_id == s.id)).scalar_one_or_none():
        raise Conflict("This sample is already evidence in the case", code="duplicate")
    e = _create(db, p, c, kind="malware_sample", title=title or f"Sample {s.filenames[0] if s.filenames else s.sha256[:12]}", description=description,
                source=s.source_note or "Malware Analysis quarantine", collected_at=s.created_at, location=location or "Platform quarantine (neutralised)",
                filename=s.filenames[0] if s.filenames else "", size=s.size, hashes={"sha256": s.sha256, "sha1": s.sha1, "md5": s.md5},
                storage_key=None, sample_id=s.id, origin={"type": "malware_sample", "sample_id": s.id})
    db.commit()
    return e


def add_events(db: Session, p, case_id: int, *, event_ids: list[int], alert_id: int | None, title: str, description: str) -> Evidence:
    c = _open_case(db, case_id)
    ids = list(dict.fromkeys(event_ids))
    if alert_id:
        ids += [i for (i,) in db.execute(select(AlertEvent.event_id).where(AlertEvent.alert_id == alert_id)) if i not in ids]
    if not ids or len(ids) > 5000:
        raise AppError("Select between 1 and 5000 events (or an alert with events)", code="validation_error", status_code=422)
    rows = db.execute(select(SecurityEvent).where(SecurityEvent.id.in_(ids)).order_by(SecurityEvent.occurred_at, SecurityEvent.id)).scalars().all()
    if not rows:
        raise NotFound("None of the events exist")
    payload = "\n".join(json.dumps({**_event_dict(r), "raw": r.raw}, default=str, sort_keys=True) for r in rows).encode() + b"\n"
    sp = spool(io.BytesIO(payload), 256 * 1024 * 1024)
    try:
        key = f"evidence/{c.id}/{uuid.uuid4().hex}.jsonl"
        get_storage().put(key, sp.file, sp.size)
    finally:
        sp.close()
    demo = any(r.is_demo for r in rows)
    e = _create(db, p, c, kind="log_export", title=title or f"SIEM export ({len(rows)} events)", description=(description + ("\nContains DEMO events." if demo else "")).strip(),
                source="CYBER RANGE SIEM", collected_at=utcnow(), location="Platform object storage", filename=f"siem-export-{len(rows)}.jsonl", size=sp.size,
                hashes={"sha256": sp.sha256, "sha1": sp.sha1, "md5": sp.md5}, storage_key=key,
                origin={"type": "siem_export", "event_ids": [r.id for r in rows][:5000], "alert_id": alert_id, "contains_demo": demo})
    db.commit()
    return e


# ------------------------------------------------------------------ custody operations
def lock(db, eid: int) -> Evidence:
    e = db.execute(select(Evidence).where(Evidence.id == eid).with_for_update()).scalar_one_or_none()
    if not e:
        raise NotFound("Evidence not found")
    return e


def verify(db: Session, p, e: Evidence) -> dict:
    if not e.storage_key and e.sample_id:
        s = db.get(FileSample, e.sample_id)
        from app.malware.service import load_bytes
        observed = hashlib.sha256(load_bytes(s)).hexdigest() if s else None
    else:
        observed, _ = get_storage().sha256(e.storage_key)
    ok = observed == e.sha256
    e.integrity, e.last_verified_at = ("verified" if ok else "mismatch"), utcnow()
    custody(db, e, "verified", p, reason="Integrity verification (SHA-256 recomputed from stored bytes)", sha256=observed, result="match" if ok else "mismatch")
    record(db, "forensics.evidence.verify", outcome="success" if ok else "failure", actor=p, resource_type="evidence", resource_id=e.id,
           details={"expected": e.sha256, "observed": observed})
    db.commit()
    return {"match": ok, "expected": e.sha256, "observed": observed}


def transfer(db: Session, p, e: Evidence, to_user_id: int, reason: str, location: str) -> None:
    from app.iam.deps import effective_permissions
    if e.custodian_id != p.id:
        c = db.get(ForensicCase, e.case_id)
        if c.lead_id != p.id:
            raise Forbidden("Only the current custodian or the case lead can transfer custody")
    to = db.execute(select(User).where(User.id == to_user_id, User.deleted_at.is_(None), User.is_active.is_(True))).scalar_one_or_none()
    if not to:
        raise NotFound("Recipient not found")
    if "evidence.manage" not in effective_permissions(to):
        raise AppError("The recipient must hold evidence.manage", code="recipient_not_authorised", status_code=422)
    if to.id == e.custodian_id:
        raise Conflict("That user is already the custodian", code="invalid_state")
    frm = db.get(User, e.custodian_id) if e.custodian_id else None
    custody(db, e, "transferred", p, reason=reason, location=location, frm=frm.username if frm else None, to=to.username)
    e.custodian_id = to.id
    record(db, "forensics.evidence.transfer", actor=p, resource_type="evidence", resource_id=e.id, details={"to": to.username})
    db.commit()


def set_status(db: Session, p, e: Evidence, status: str, reason: str) -> None:
    if e.is_sealed and status != "released":
        raise Conflict("Sealed evidence can only be released", code="sealed")
    if status == e.status:
        raise Conflict(f"Evidence is already {status}", code="invalid_state")
    prev = e.status
    custody(db, e, "status_changed", p, reason=reason, details={"from": prev, "to": status})
    e.status = status
    record(db, "forensics.evidence.status", actor=p, resource_type="evidence", resource_id=e.id, details={"from": prev, "to": status})
    db.commit()


def seal(db: Session, p, e: Evidence, reason: str) -> None:
    if e.is_sealed:
        raise Conflict("Evidence is already sealed", code="invalid_state")
    res = verify(db, p, e)  # sealing always records a fresh integrity check first
    if not res["match"]:
        raise Conflict("Integrity check failed; evidence cannot be sealed", code="integrity_mismatch")
    e = lock(db, e.id)
    custody(db, e, "sealed", p, reason=reason, sha256=res["observed"], result="sealed")
    e.is_sealed, e.status = True, "preserved"
    record(db, "forensics.evidence.seal", actor=p, resource_type="evidence", resource_id=e.id)
    db.commit()


def note(db: Session, p, e: Evidence, text: str) -> None:
    custody(db, e, "note", p, reason=text)
    db.commit()


def open_download(db: Session, p, e: Evidence, reason: str):
    if not e.storage_key:
        raise Conflict("Malware samples are not downloadable; analyse them in Malware Analysis", code="not_downloadable")
    custody(db, e, "accessed", p, reason=reason, details={"operation": "download"})
    record(db, "forensics.evidence.download", actor=p, resource_type="evidence", resource_id=e.id, details={"reason": reason[:300]})
    db.commit()
    return get_storage().open_iter(e.storage_key)


def report_markdown(db: Session, c: ForensicCase, users: dict) -> str:
    items = db.execute(select(Evidence).where(Evidence.case_id == c.id).order_by(Evidence.id)).scalars().all()
    out = [f"# Chain of custody report: {c.reference}", "", f"**{c.title}**", "", f"- Status: {c.status} · classification: {c.classification}",
           f"- Lead: {users.get(c.lead_id)} · opened {c.created_at} UTC" + (f" · closed {c.closed_at} UTC" if c.closed_at else ""),
           f"- Linked incident: #{c.incident_id}" if c.incident_id else "- Linked incident: none", "", c.description or "", "",
           f"Generated {utcnow().isoformat(timespec='seconds')} UTC by CYBER RANGE. Times are UTC.", "", "## Evidence register", "",
           "| Ref | Kind | Title | SHA-256 | Size | Custodian | Integrity | Sealed |", "|---|---|---|---|---|---|---|---|"]
    for e in items:
        out.append(f"| {e.reference} | {e.kind} | {e.title} | `{e.sha256}` | {e.size} | {users.get(e.custodian_id)} | {e.integrity} | {'yes' if e.is_sealed else 'no'} |")
    for e in items:
        chain = verify_chain(db, e)
        hashes = db.execute(select(EvidenceHash).where(EvidenceHash.evidence_id == e.id).order_by(EvidenceHash.algorithm)).scalars().all()
        out += ["", f"## {e.reference} · {e.title}", "", f"- Source: {e.source or '—'} · collected {e.collected_at} UTC by {users.get(e.collected_by)}",
                f"- File: {e.filename or '—'} ({e.size} bytes) · status {e.status}", *[f"- {h.algorithm.upper()}: `{h.value}`" for h in hashes],
                f"- Custody log: {chain['entries']} entries, hash chain {'intact' if chain['valid'] else 'BROKEN at entry ' + str(chain['broken_at'])}", "",
                "| # | Time (UTC) | Action | By | From → To | Reason | SHA-256 observed | Result |", "|---|---|---|---|---|---|---|---|"]
        for ev in db.execute(select(CustodyEvent).where(CustodyEvent.evidence_id == e.id).order_by(CustodyEvent.seq)).scalars():
            reason = ev.reason.replace("|", "\\|").replace("\n", " ")
            out.append(f"| {ev.seq} | {ev.at.isoformat(timespec='seconds')} | {ev.action} | {ev.actor_label} | {ev.from_custodian or ''} → {ev.to_custodian or ''} | "
                       f"{reason} | {('`' + ev.sha256_observed[:16] + '…`') if ev.sha256_observed else ''} | {ev.result or ''} |")
    return "\n".join(out) + "\n"


def counts(db: Session) -> dict:
    open_cases = db.execute(select(func.count()).select_from(ForensicCase).where(ForensicCase.status == "open")).scalar_one()
    total = db.execute(select(func.count()).select_from(Evidence)).scalar_one()
    mismatch = db.execute(select(func.count()).select_from(Evidence).where(Evidence.integrity == "mismatch")).scalar_one()
    return {"cases_open": open_cases, "evidence_total": total, "evidence_integrity_mismatch": mismatch}
