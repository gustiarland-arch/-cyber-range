"""Purple team: for every executed assessment step, was the technique detected by the SOC?

A step is "attacked" once it started. It is "detected" when an alert was raised from events whose source is the
assessment's attacker address inside the step's time window (plus a short grace period for threshold rules, which never
reaches into the next step: an event is credited to the latest step that had started when it occurred):
  * detected_same_technique: an alerting rule maps to the step's ATT&CK technique (or its parent technique);
  * detected_other: an alert fired for the attacker in the window, but from a rule mapped to another technique;
  * not detected otherwise.
Each detection says where its evidence came from: sensor telemetry (Zeek, Suricata, Wazuh, syslog) or the platform's own
record of what the assessment did (dataset redteam.activity). Only sensor evidence proves that the network saw it.
"""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blueteam.attack import technique_name
from app.blueteam.models import Alert, AlertEvent, DetectionRule, SecurityEvent
from app.core.database import utcnow
from app.redteam.actions import ACTIONS
from app.redteam.models import Assessment, AssessmentEvent

GRACE = timedelta(minutes=2)
ACTIVITY_DATASET = "redteam.activity"


def _parent(t: str | None) -> str | None:
    return t.split(".")[0] if t else None


def assessment_steps(db: Session, a: Assessment) -> list[dict]:
    evs = db.execute(select(AssessmentEvent).where(AssessmentEvent.assessment_id == a.id).order_by(AssessmentEvent.id)).scalars().all()
    starts = {e.step_index: e for e in evs if e.kind == "step_started"}
    ends = {e.step_index: e for e in evs if e.kind in ("step_finished",)}
    end_all = a.finished_at or utcnow()
    rows = db.execute(
        select(Alert.id, Alert.title, Alert.severity, Alert.status, DetectionRule.code, DetectionRule.mitre_technique, SecurityEvent.occurred_at, SecurityEvent.dataset)
        .join(AlertEvent, AlertEvent.alert_id == Alert.id).join(SecurityEvent, SecurityEvent.id == AlertEvent.event_id)
        .join(DetectionRule, DetectionRule.id == Alert.rule_id)
        .where(SecurityEvent.src_ip == a.attacker_ip, SecurityEvent.occurred_at.between((a.started_at or end_all) - timedelta(seconds=5), end_all + GRACE))
    ).all() if a.started_at and a.attacker_ip else []
    # Each event belongs to the most recent step that had started when it happened (steps are sequential); the grace
    # period only extends a step until the next one begins, so a later step's alerts are never credited to an earlier one.
    order = sorted((e.at, i) for i, e in starts.items())

    def owner(at):
        cur = order[0][1] if order and at >= order[0][0] - timedelta(seconds=5) else None  # clock skew lead-in, first step only
        for t, i in order:
            if t <= at:
                cur = i
            else:
                break
        return cur

    out = []
    for i, step in enumerate(a.scenario["steps"]):
        meta = ACTIONS.get(step["action"], {})
        tech = meta.get("mitre")
        st = starts.get(i)
        row = {"step": i, "title": step.get("title") or meta.get("title"), "action": step["action"], "technique": tech,
               "technique_name": technique_name(tech), "tactic": meta.get("tactic"), "attacked": bool(st), "detected": False,
               "detected_same_technique": False, "alerts": [], "evidence": [], "detected_after_seconds": None}
        if st:
            lo = st.at - timedelta(seconds=5)
            hi = (ends[i].at if i in ends else end_all) + GRACE
            seen = {}
            for aid, title, sev, status, code, rtech, at, ds in rows:
                if lo <= at <= hi and owner(at) == i:
                    same = bool(rtech and tech and (_parent(rtech) == _parent(tech)))
                    s = seen.setdefault(aid, {"id": aid, "title": title, "severity": sev, "status": status, "rule": code, "technique": rtech,
                                              "same_technique": same, "sources": set(), "first_at": at})
                    s["sources"].add("platform" if ds == ACTIVITY_DATASET else "sensor")
                    s["first_at"] = min(s["first_at"], at)
            row["alerts"] = [{**v, "sources": sorted(v["sources"]),
                              "detected_after_seconds": max(0.0, round((v["first_at"] - st.at).total_seconds(), 1))} for v in seen.values()]
            for v in row["alerts"]:
                v["first_at"] = v["first_at"].isoformat() + "Z"
            row["detected_after_seconds"] = min((v["detected_after_seconds"] for v in row["alerts"]), default=None)
            row["detected"] = bool(seen)
            row["detected_same_technique"] = any(v["same_technique"] for v in seen.values())
            row["evidence"] = sorted({s for v in seen.values() for s in v["sources"]})
        out.append(row)
    return out


def summary(db: Session, days: int = 30, lab_id: int | None = None) -> dict:
    since = utcnow() - timedelta(days=days)
    q = select(Assessment).where(Assessment.started_at.is_not(None), Assessment.started_at >= since)
    if lab_id:
        q = q.where(Assessment.lab_id == lab_id)
    assessments = db.execute(q.order_by(Assessment.started_at.desc()).limit(200)).scalars().all()
    techs: dict[str, dict] = {}
    per = []
    for a in assessments:
        steps = assessment_steps(db, a)
        att = [s for s in steps if s["attacked"]]
        per.append({"id": a.id, "title": a.title, "status": a.status, "scenario": a.scenario.get("code"), "lab": a.scope.get("lab_name"),
                    "started_at": a.started_at, "steps": len(att), "detected": sum(1 for s in att if s["detected"]),
                    "detected_same": sum(1 for s in att if s["detected_same_technique"])})
        for s in att:
            t = techs.setdefault(s["technique"], {"technique": s["technique"], "name": s["technique_name"], "tactic": s["tactic"], "attacked": 0,
                                                  "detected": 0, "detected_same": 0, "sensor": 0, "last_attacked": None, "rules": set()})
            t["attacked"] += 1
            t["detected"] += int(s["detected"])
            t["detected_same"] += int(s["detected_same_technique"])
            t["sensor"] += int("sensor" in s["evidence"])
            t["rules"] |= {x["rule"] for x in s["alerts"]}
            t["last_attacked"] = max(filter(None, [t["last_attacked"], a.started_at]))
    rows = []
    for t in techs.values():
        rate = t["detected"] / t["attacked"] if t["attacked"] else 0
        rows.append({**t, "rules": sorted(t["rules"]), "detection_rate": round(rate, 3),
                     "verdict": "detected" if t["detected_same"] == t["attacked"] else "partial" if t["detected"] else "missed"})
    rows.sort(key=lambda r: (r["detection_rate"], r["technique"] or ""))
    total = sum(r["attacked"] for r in rows)
    return {"days": days, "assessments": per, "techniques": rows, "attacked_steps": total,
            "detected_steps": sum(r["detected"] for r in rows), "detected_same_steps": sum(r["detected_same"] for r in rows)}


def report_markdown(db: Session, days: int = 30) -> str:
    s = summary(db, days)
    out = [f"# Purple team report: attacked vs detected (last {days} days)", "",
           f"- Assessments analysed: {len(s['assessments'])}", f"- Steps executed: {s['attacked_steps']}",
           f"- Steps detected (any alert): {s['detected_steps']}", f"- Steps detected by a rule for the same technique: {s['detected_same_steps']}", "",
           "| Technique | Tactic | Attacked | Detected | Same technique | Sensor evidence | Verdict | Rules |", "|---|---|---|---|---|---|---|---|"]
    out += [f"| {r['technique']} {r['name'] or ''} | {r['tactic'] or ''} | {r['attacked']} | {r['detected']} | {r['detected_same']} | {r['sensor']} | "
            f"{r['verdict']} | {', '.join(r['rules']) or '—'} |" for r in s["techniques"]]
    out += ["", "Verdict: detected = every execution raised an alert from a rule mapped to the same technique; partial = some alert fired; "
            "missed = no alert. Sensor evidence counts detections backed by Zeek/Suricata/Wazuh/syslog events rather than only the platform's "
            "own activity record.", ""]
    return "\n".join(out)
