"""Real network sensors inside labs: Zeek and Suricata capturing a lab's isolated bridge networks.

How it works
  * A lab operator attaches sensors to a running lab. For every selected lab network the lab worker starts one passive
    capture container per sensor kind. The container shares the host network namespace only so it can open the lab
    bridge (br-<network id>) in promiscuous mode; it gets no other capability than packet capture (NET_RAW/NET_ADMIN;
    Suricata also SYS_NICE and DAC_READ_SEARCH to read its root-only config), no-new-privileges, a memory/CPU/pid limit and tmpfs-only log storage. Images are fixed by the
    platform (env CR_SENSOR_ZEEK_IMAGE / CR_SENSOR_SURICATA_IMAGE), never chosen by users.
  * Every 10 s the lab worker reads new complete lines from the sensors' JSON logs (Zeek conn/dns/http/ssl/ssh/notice/
    weird/files, Suricata eve.json) and ingests them into a per-sensor log source, so normal detection rules, threat-intel
    matching and the purple-team report see real packet-level telemetry.
  * Suricata runs a small platform ruleset (below) that recognises the lab detection tests and generic scans. Add ET Open
    or your own rules by building a derived image and pointing CR_SENSOR_SURICATA_IMAGE at it.
  * Sensors are removed when the lab stops or is destroyed, and whenever the kill switch stops labs.
"""
import base64
import json
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam import service as soc
from app.blueteam.models import LogSource
from app.core.database import SessionLocal, utcnow
from app.core.errors import AppError, Conflict, NotFound
from app.core.logging import log
from app.cyber_range.engine.driver import DriverError, SensorSpec, bridge_name, get_driver
from app.cyber_range.models import SENSOR_KINDS, Lab, LabEvent, LabInstance, LabSensor

ZEEK_LOGS = ("conn", "dns", "http", "ssl", "ssh", "notice", "weird", "files")
READ_LIMIT = 2_000_000          # bytes per file per collection run
MAX_RECORDS = 4000              # per sensor per run (ingest batch limit is 5000)

SURICATA_RULES = r"""
alert http any any -> any any (msg:"CR-LAB SQL injection pattern in URI"; flow:established,to_server; http.uri; content:"union"; nocase; content:"select"; nocase; distance:0; classtype:web-application-attack; sid:9100001; rev:1;)
alert http any any -> any any (msg:"CR-LAB path traversal in URI"; flow:established,to_server; http.uri.raw; content:"../"; classtype:web-application-attack; sid:9100002; rev:1;)
alert http any any -> any any (msg:"CR-LAB /etc/passwd requested"; flow:established,to_server; http.uri.raw; content:"/etc/passwd"; classtype:web-application-attack; sid:9100003; rev:1;)
alert http any any -> any any (msg:"CR-LAB script tag in URI"; flow:established,to_server; http.uri; content:"<script"; nocase; classtype:web-application-attack; sid:9100004; rev:1;)
alert dns any any -> any any (msg:"CR-LAB DNS query for suspicious TLD"; dns.query; pcre:"/\.(xyz|top|zip|mov|tk|gq|cf|ml)$/i"; classtype:bad-unknown; sid:9100005; rev:1;)
alert tcp any any -> any any (msg:"CR-LAB possible TCP port scan"; flow:stateless; flags:S,12; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:9100006; rev:1;)
alert icmp any any -> any any (msg:"CR-LAB ICMP sweep"; itype:8; threshold:type both, track by_src, count 10, seconds 10; classtype:attempted-recon; sid:9100007; rev:1;)
""".strip()


def images() -> dict:
    return {"zeek": os.environ.get("CR_SENSOR_ZEEK_IMAGE", "zeek/zeek:7.0.5"),
            "suricata": os.environ.get("CR_SENSOR_SURICATA_IMAGE", "jasonish/suricata:7.0.8")}


def _spec(s: LabSensor, inst: LabInstance) -> SensorSpec:
    labels = {"cyber-range.managed": "true", "cyber-range.instance": inst.runtime_id, "cyber-range.lab": str(inst.lab_id),
              "cyber-range.sensor": s.kind, "cyber-range.subnet": s.subnet_key}
    name = f"cr-{inst.runtime_id}-sensor-{s.kind}-{s.id}"
    if s.kind == "zeek":
        cmd = ["sh", "-c", f"mkdir -p /logs && cd /logs && exec zeek -C -i {s.interface} local LogAscii::use_json=T"]
        return SensorSpec(name=name, image=s.image_ref, labels=labels, command=cmd, cap_add=["NET_RAW", "NET_ADMIN"], tmpfs=["/logs"], memory_mb=768)
    rules = base64.b64encode(SURICATA_RULES.encode()).decode()
    # the image entrypoint is bypassed; DAC_READ_SEARCH only lets root read the suricata-owned config, nothing is writable outside tmpfs
    cmd = ["-c", f"mkdir -p /var/log/suricata /tmp/cr && echo {rules} | base64 -d > /tmp/cr/cr-lab.rules && "
           f"exec suricata -i {s.interface} -S /tmp/cr/cr-lab.rules -l /var/log/suricata -k none"]
    return SensorSpec(name=name, image=s.image_ref, labels=labels, command=cmd, entrypoint=["sh"], cap_add=["NET_RAW", "NET_ADMIN", "SYS_NICE", "DAC_READ_SEARCH"],
                      tmpfs=["/var/log/suricata", "/tmp/cr", "/var/run/suricata"], memory_mb=1024)


def files_for(kind: str) -> list[tuple[str, str | None]]:
    """[(path inside the sensor, zeek log name)]"""
    if kind == "agent":       # host agent inside an office lab node (app/cyber_range/office.py)
        return [("/var/log/cr/events.jsonl", None)]
    if kind == "zeek":
        return [(f"/logs/{n}.log", n) for n in ZEEK_LOGS]
    return [("/var/log/suricata/eve.json", None)]


# ------------------------------------------------------------------ API side
def sensor_out(s: LabSensor) -> dict:
    return {"id": s.id, "kind": s.kind, "subnet_key": s.subnet_key, "interface": s.interface, "image": s.image_ref, "status": s.status,
            "log_source_id": s.log_source_id, "events_total": s.events_total, "last_event_at": s.last_event_at, "error": s.error,
            "created_at": s.created_at, "stopped_at": s.stopped_at}


def list_for_lab(db: Session, lab: Lab) -> list[dict]:
    rows = db.execute(select(LabSensor).where(LabSensor.lab_id == lab.id).order_by(LabSensor.id.desc()).limit(50)).scalars()
    return [sensor_out(s) for s in rows]


def attach(db: Session, p, lab: Lab, kinds: list[str], subnets: list[str] | None) -> list[LabSensor]:
    bad = set(kinds) - set(SENSOR_KINDS)
    if bad or not kinds:
        raise AppError("Choose zeek and/or suricata", code="validation_error", status_code=422)
    inst = db.execute(select(LabInstance).where(LabInstance.lab_id == lab.id, LabInstance.status == "running")
                      .order_by(LabInstance.id.desc()).limit(1)).scalar_one_or_none()
    if not inst:
        raise Conflict("The lab is not running", code="lab_not_running")
    nets = {n.subnet_key: n for n in inst.networks}
    chosen = subnets or list(nets)
    unknown = [k for k in chosen if k not in nets]
    if unknown:
        raise AppError(f"Unknown lab network(s): {', '.join(unknown)}", code="validation_error", status_code=422)
    active = {(s.kind, s.subnet_key) for s in db.execute(select(LabSensor).where(LabSensor.instance_id == inst.id, LabSensor.status.in_(("pending", "starting", "running")))).scalars()}
    img = images()
    # The API process has no Docker socket (only the lab worker does): the bridge name is derived from the network id.
    out = []
    for kind in kinds:
        for key in chosen:
            if (kind, key) in active:
                continue
            old = db.execute(select(LabSensor).where(LabSensor.instance_id == inst.id, LabSensor.kind == kind, LabSensor.subnet_key == key)).scalar_one_or_none()
            if old:
                db.delete(old)
                db.flush()
            src_name = f"Lab #{lab.id} {lab.name[:60]} · {kind} · {key}"[:128]
            src = db.execute(select(LogSource).where(LogSource.name == src_name)).scalar_one_or_none()
            if not src:
                src = LogSource(name=src_name, kind=kind, lab_id=lab.id, is_demo=False,
                                description=f"{kind} sensor capturing lab network '{key}' (isolated bridge). Collected by the lab worker; no ingest key.")
                db.add(src)
                db.flush()
            s = LabSensor(lab_id=lab.id, instance_id=inst.id, kind=kind, subnet_key=key, interface=bridge_name(nets[key].docker_id or ""),
                          image_ref=img[kind], status="pending", log_source_id=src.id, offsets={}, created_by=p.id)
            db.add(s)
            out.append(s)
    db.flush()
    if not out:
        raise Conflict("Those sensors are already running", code="sensors_running")
    db.add(LabEvent(lab_id=lab.id, instance_id=inst.id, kind="sensor.attach", level="info",
                    message=f"Sensors requested by {p.username}: {', '.join(f'{s.kind}@{s.subnet_key}' for s in out)}"))
    record(db, "lab.sensor.attach", actor=p, resource_type="lab", resource_id=lab.id, details={"sensors": [[s.kind, s.subnet_key] for s in out]})
    return out


def detach(db: Session, p, lab: Lab, sensor_id: int | None) -> list[int]:
    q = select(LabSensor).where(LabSensor.lab_id == lab.id, LabSensor.status.in_(("pending", "starting", "running", "failed")))
    if sensor_id:
        q = q.where(LabSensor.id == sensor_id)
    else:   # "detach all" means the network sensors; host agents of office nodes are stopped one by one
        q = q.where(LabSensor.kind.in_(SENSOR_KINDS))
    rows = db.execute(q).scalars().all()
    if sensor_id and not rows:
        raise NotFound("Sensor not found")
    for s in rows:
        s.status = "stopping"
    record(db, "lab.sensor.detach", actor=p, resource_type="lab", resource_id=lab.id, details={"sensors": [s.id for s in rows]})
    return [s.id for s in rows]


def dispatch(op: str, ids: list[int]) -> None:
    if not ids:
        return
    if os.environ.get("CR_LAB_EXECUTION", "celery") == "inline":
        (start_sensors if op == "start" else stop_sensors)(ids)
        return
    from app.core.celery_app import celery_app
    celery_app.send_task(f"app.cyber_range.tasks.sensors_{op}", args=[ids], queue="lab")


# ------------------------------------------------------------------ lab worker side
def start_sensors(ids: list[int]) -> int:
    d = get_driver()
    n = 0
    with SessionLocal() as db:
        for s in db.execute(select(LabSensor).where(LabSensor.id.in_(ids), LabSensor.status == "pending")).scalars().all():
            inst = db.get(LabInstance, s.instance_id)
            s.status = "starting"
            db.commit()
            try:
                if not inst or inst.status != "running":
                    raise DriverError("the lab is no longer running")
                d.ensure_image(s.image_ref)
                s.docker_id = d.create_sensor(_spec(s, inst))
                s.status, s.error = "running", None
                db.add(LabEvent(lab_id=s.lab_id, instance_id=s.instance_id, kind="sensor.started", message=f"{s.kind} sensor capturing {s.subnet_key} ({s.interface})"))
                n += 1
            except DriverError as e:
                s.status, s.error = "failed", str(e)[:2000]
                db.add(LabEvent(lab_id=s.lab_id, instance_id=s.instance_id, kind="sensor.failed", level="error", message=f"{s.kind} sensor on {s.subnet_key} failed: {e}"[:512]))
            db.commit()
    return n


def _remove(db: Session, d, s: LabSensor, reason: str) -> None:
    if s.docker_id and s.kind != "agent":     # an agent "sensor" is the lab node itself: the lab lifecycle owns it
        try:
            d.remove_container(s.docker_id)
        except DriverError:
            log.exception("sensor_remove_failed", sensor=s.id)
    s.status, s.stopped_at = "stopped", utcnow()
    db.add(LabEvent(lab_id=s.lab_id, instance_id=s.instance_id, kind="sensor.stopped", message=f"{s.kind} sensor on {s.subnet_key} stopped ({reason})"))


def stop_sensors(ids: list[int]) -> int:
    d = get_driver()
    with SessionLocal() as db:
        rows = db.execute(select(LabSensor).where(LabSensor.id.in_(ids), LabSensor.status == "stopping")).scalars().all()
        for s in rows:
            collect_one(db, d, s)   # keep what was captured until now
            _remove(db, d, s, "detached")
        db.commit()
        return len(rows)


def stop_for_instance(db: Session, d, inst: LabInstance, reason: str) -> None:
    """Called by lab lifecycle operations (stop, destroy) inside their transaction."""
    for s in db.execute(select(LabSensor).where(LabSensor.instance_id == inst.id, LabSensor.status.in_(("pending", "starting", "running", "stopping")))).scalars():
        _remove(db, d, s, reason)


def collect_one(db: Session, d, s: LabSensor) -> int:
    if not s.docker_id or not s.log_source_id:
        return 0
    src = db.get(LogSource, s.log_source_id)
    if not src or not src.is_enabled:
        return 0
    offsets = dict(s.offsets or {})
    total = 0
    for path, zlog in files_for(s.kind):
        off = int(offsets.get(path, 0))
        try:
            chunk = d.read_file(s.docker_id, path, off, READ_LIMIT)
        except DriverError as e:
            s.error = str(e)[:2000]
            continue
        end = chunk.rfind(b"\n")
        if end < 0:
            continue
        records = []
        for line in chunk[:end].splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            records.append(r)
        offsets[path] = off + end + 1
        for i in range(0, len(records), MAX_RECORDS):
            res = soc.ingest(db, src, records[i:i + MAX_RECORDS], kind="json" if s.kind == "agent" else s.kind,
                             dataset_hint=f"zeek.{zlog}" if zlog else None)
            total += res["accepted"]
    s.offsets = offsets
    if total:
        s.events_total = (s.events_total or 0) + total
        s.last_event_at = utcnow()
    return total


def collect() -> int:
    d = get_driver()
    n = 0
    with SessionLocal() as db:
        for sid in db.execute(select(LabSensor.id).where(LabSensor.status == "running")).scalars().all():
            s = db.get(LabSensor, sid)
            if s.kind == "agent" and d.state(s.docker_id) != "running":
                continue              # the lab node is stopped or restarting; the lab lifecycle decides
            if d.state(s.docker_id) != "running":
                s.status, s.error = "failed", f"sensor container is {d.state(s.docker_id)}"
                db.commit()
                continue
            try:
                n += collect_one(db, d, s)
            except Exception:  # noqa: BLE001 - one broken sensor must not stop the others
                db.rollback()
                log.exception("sensor_collect_failed", sensor=sid)
            db.commit()
    return n
