// Pure functions that turn the /labs/{id}/live response into what the 3D scene draws at a point in time.
// Kept free of Three.js so they can be unit tested and reused by the timeline UI.

export const STATE_COLOR = { running: '#22c55e', pending: '#f59e0b', stopped: '#64748b', error: '#f43f5e', absent: '#334155' }
export const STATE_LABEL = { running: 'berjalan', pending: 'transisi', stopped: 'mati', error: 'error', absent: 'tidak di-deploy' }
export const SEV_COLOR = ['#22d3ee', '#22d3ee', '#f59e0b', '#f97316', '#f43f5e']
export const RECENT_BUCKETS = 5 // particles reflect activity in the last N buckets before the cursor

const ms = (iso) => (iso ? Date.parse(iso) : NaN)

/** Window helpers: bucket index of a timestamp and the timestamp of a bucket end. */
export function windowOf(live) {
  const start = ms(live.window.start), end = ms(live.window.end)
  const n = live.window.buckets || 60
  const size = (end - start) / n
  return { start, end, n, size, bucketAt: (t) => Math.max(0, Math.min(n - 1, Math.floor((t - start) / size))) }
}

/** Flow state at time t: cumulative count (line thickness) and recent count (particles). */
export function flowsAt(live, t) {
  const w = windowOf(live)
  const i = w.bucketAt(t)
  const out = []
  for (const f of live.traffic?.flows || []) {
    let total = 0, recent = 0
    for (let b = 0; b <= i; b++) {
      total += f.buckets[b] || 0
      if (b > i - RECENT_BUCKETS) recent += f.buckets[b] || 0
    }
    if (!total) continue
    out.push({ ...f, total, recent, src: f.src || `ext:${f.src_ip}`, dst: f.dst || `ext:${f.dst_ip}` })
  }
  return out
}

/** Line radius from a cumulative connection count (log scale, so 10x traffic is visibly but not absurdly thicker). */
export const flowRadius = (count) => Math.min(0.3, 0.03 + 0.035 * Math.log2(1 + count))
/** Number of particles for recent activity (0 when the pair was quiet in the recent buckets). */
export const flowParticles = (recent) => (recent ? Math.min(6, 1 + Math.floor(Math.log2(1 + recent))) : 0)

export const OPEN_ALERT = ['new', 'acknowledged', 'in_progress']

/**
 * Alerts that make a node blink at t, and all alerts seen up to t, per node key.
 * Replay: an alert blinks from its first event until a short grace after its last event.
 * Live (following): an alert also keeps blinking while it is still open, until an analyst handles it.
 */
export function alertsAt(live, t, { following = false } = {}) {
  const w = windowOf(live)
  const grace = Math.max(60_000, w.size * 3)
  const blinking = new Map(), seen = new Map()
  for (const a of live.alerts || []) {
    const first = ms(a.first_seen), last = ms(a.last_seen)
    if (first > t) continue
    const active = t <= last + grace || (following && OPEN_ALERT.includes(a.status))
    for (const n of a.nodes) {
      const s = seen.get(n.key) || []
      s.push(a)
      seen.set(n.key, s)
      if (active) blinking.set(n.key, Math.max(blinking.get(n.key) ?? 0, a.severity))
    }
  }
  return { blinking, seen }
}

/** Red team step states at t for one assessment: which path is lit now and which were already walked. */
export function stepsAt(assessment, t, now = Date.now()) {
  if (!assessment) return []
  return assessment.steps.map((s) => {
    const start = ms(s.started_at), end = s.finished_at ? ms(s.finished_at) : (s.state === 'running' ? now : NaN)
    let phase = 'pending'
    if (start <= t) phase = Number.isFinite(end) && end < t ? 'done' : 'active'
    if (phase === 'active' && !Number.isFinite(end) && s.state !== 'running') phase = 'done'
    return { ...s, phase }
  })
}

/** Choose which assessment the view follows by default: a running one, else the most recent. */
export function defaultAssessment(live) {
  const list = live.assessments || []
  return list.find((a) => a.status === 'running') || list[0] || null
}

/** Markers for the replay bar: red team steps, alerts and lab lifecycle events, positioned 0..1 in the window. */
export function timelineMarkers(live, assessment) {
  const w = windowOf(live)
  const pos = (iso) => (ms(iso) - w.start) / (w.end - w.start)
  const out = []
  for (const s of assessment?.steps || []) if (s.started_at) out.push({ kind: 'step', at: s.started_at, x: pos(s.started_at), label: `Langkah ${s.index + 1}: ${s.title}` })
  for (const a of live.alerts || []) out.push({ kind: 'alert', at: a.first_seen, x: pos(a.first_seen), severity: a.severity, label: a.title })
  for (const e of live.lab_events || []) out.push({ kind: e.level === 'error' ? 'lab-error' : 'lab', at: e.at, x: pos(e.at), label: e.message })
  return out.filter((m) => m.x >= 0 && m.x <= 1).sort((a, b) => a.x - b.x)
}

/**
 * Merge markers closer than `gap` (fraction of the bar) so none hides another. A cluster takes the colour of its
 * most important item (red team step > highest alert > lab error > lab event) and jumps to its earliest time.
 */
export function clusterMarkers(markers, gap = 0.008) {
  const rank = (m) => (m.kind === 'step' ? 10 : m.kind === 'alert' ? 5 + (m.severity || 0) : m.kind === 'lab-error' ? 3 : 1)
  const out = []
  for (const m of markers) {
    const last = out[out.length - 1]
    if (last && m.x - last.x0 <= gap) {
      last.items.push(m)
      if (rank(m) > rank(last)) Object.assign(last, { kind: m.kind, severity: m.severity })
      last.x = (last.x0 + m.x) / 2
    } else out.push({ kind: m.kind, severity: m.severity, at: m.at, x: m.x, x0: m.x, label: m.label, items: [m] })
  }
  return out
}

/** External (non-lab) endpoints that appear in flows, as ghost nodes. */
export function externalNodes(live) {
  return (live.traffic?.external || []).map((e) => ({ key: `ext:${e.ip}`, ip: e.ip, events: e.events }))
}

// ------------------------------------------------------------------ status history (replay)
/**
 * State of a node at t. Live (following) uses the current state. Replay starts from the reconstructed state at the
 * window start and applies lab lifecycle changes (all nodes) and reconcile changes (one node) up to t. Without any
 * recorded history the current state is the best available answer, and `known` says so.
 */
export function nodeStateAt(live, key, t, { following = false } = {}) {
  const current = live.nodes.find((n) => n.key === key)?.state || 'absent'
  if (following) return { state: current, known: true }
  const h = live.status_history || { initial: {}, changes: [] }
  let state = h.initial[key] ?? h.initial['*'] ?? null
  for (const c of h.changes) {
    if (ms(c.at) > t) break
    if (c.node === null || c.node === key) state = c.state
  }
  if (state === null) {
    // nothing recorded before t: if a later change exists, the node was in the state that change left (unknown) -> current
    return { state: current, known: !h.changes.length }
  }
  // a node the topology never deployed stays absent regardless of lab-wide lifecycle events
  if (current === 'absent' && !live.nodes.find((n) => n.key === key)?.name) return { state: 'absent', known: true }
  return { state, known: true }
}

// ------------------------------------------------------------------ purple team split
export const DETECTION_GRACE_MS = 120_000
export const VERDICT_LABEL = { pending: 'belum jalan', waiting: 'menunggu deteksi', detected: 'terdeteksi', other_rule: 'rule lain', missed: 'LOLOS' }
export const VERDICT_TONE = { pending: 'neutral', waiting: 'accent', detected: 'ok', other_rule: 'warn', missed: 'critical' }

/**
 * Blue team verdict for one red team step as it would have looked at time t:
 *   pending     step not started yet
 *   waiting     step running (or within the grace period) and no alert so far
 *   detected    an alert from a rule for the same ATT&CK technique has fired
 *   other_rule  only alerts from other rules fired
 *   missed      the step ended more than the grace period ago with no alert
 */
export function detectionAt(step, t, { following = false } = {}) {
  const start = ms(step.started_at)
  if (!(start <= t)) return { verdict: 'pending', alerts: [] }
  const d = step.detection
  const alerts = (d?.alerts || []).filter((a) => ms(a.first_at) <= t)
  if (alerts.length) {
    const same = alerts.some((a) => a.same_technique)
    return { verdict: same ? 'detected' : 'other_rule', alerts, ttd: Math.min(...alerts.map((a) => a.detected_after_seconds)),
      evidence: [...new Set(alerts.flatMap((a) => a.sources))].sort() }
  }
  const end = step.finished_at ? ms(step.finished_at) : NaN
  const over = Number.isFinite(end) ? t > end + DETECTION_GRACE_MS : false
  // live: a finished assessment's final verdict is already known from the server
  if (over || (following && d && d.verdict === 'missed' && Number.isFinite(end))) return { verdict: 'missed', alerts: [] }
  return { verdict: 'waiting', alerts: [] }
}

/** Totals for the split header: how many started steps were detected, by which rule kind, and the mean time to detect. */
export function purpleScore(assessment, t, opts = {}) {
  const rows = (assessment?.steps || []).map((s) => detectionAt(s, t, opts))
  const started = rows.filter((r) => r.verdict !== 'pending')
  const detected = started.filter((r) => r.verdict === 'detected' || r.verdict === 'other_rule')
  const ttds = detected.map((r) => r.ttd).filter((x) => Number.isFinite(x))
  return { started: started.length, detected: detected.length, same: started.filter((r) => r.verdict === 'detected').length,
    // detections backed by network sensor events (Zeek/Suricata/...). The rest rely only on the platform's own record of
    // what the red team did, which proves the rules work but not that the network actually saw the attack.
    sensor: detected.filter((r) => r.evidence?.includes('sensor')).length,
    missed: started.filter((r) => r.verdict === 'missed').length, meanTtd: ttds.length ? ttds.reduce((a, b) => a + b, 0) / ttds.length : null }
}
