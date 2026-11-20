import { describe, expect, it } from 'vitest'
import { alertsAt, clusterMarkers, defaultAssessment, flowParticles, flowRadius, flowsAt, stepsAt, timelineMarkers, windowOf } from '@/visualization-3d/liveModel'

const T0 = Date.parse('2026-11-19T10:00:00Z')
const iso = (min) => new Date(T0 + min * 60_000).toISOString()
const buckets = (pairs) => { const b = Array(60).fill(0); for (const [i, n] of pairs) b[i] = n; return b }
const live = {
  window: { start: iso(0), end: iso(60), minutes: 60, bucket_seconds: 60, buckets: 60 },
  traffic: {
    flows: [
      { src: 'ws-1', dst: 'web-1', src_ip: '10.0.0.21', dst_ip: '10.0.0.10', count: 30, max_severity: 0, buckets: buckets([[10, 10], [50, 20]]) },
      { src: 'ws-2', dst: null, src_ip: '10.0.0.22', dst_ip: '8.8.8.8', count: 2, max_severity: 3, buckets: buckets([[59, 2]]) },
    ],
    external: [{ ip: '8.8.8.8', events: 2 }],
  },
  alerts: [
    { id: 1, severity: 3, status: 'new', first_seen: iso(20), last_seen: iso(21), nodes: [{ key: 'web-1', roles: ['target'] }] },
    { id: 2, severity: 1, status: 'closed', first_seen: iso(5), last_seen: iso(6), nodes: [{ key: 'ws-1', roles: ['source'] }] },
  ],
  assessments: [{ id: 7, status: 'completed', attacker_node: 'ws-2', steps: [
    { index: 0, title: 'scan', state: 'done', started_at: iso(30), finished_at: iso(32), targets: ['web-1'] },
    { index: 1, title: 'probe', state: 'done', started_at: iso(32), finished_at: iso(35), targets: ['web-1'] },
  ] }],
  lab_events: [{ at: iso(1), level: 'info', message: 'deployed' }],
}

describe('liveModel', () => {
  it('maps time to buckets inside the window', () => {
    const w = windowOf(live)
    expect(w.bucketAt(T0)).toBe(0)
    expect(w.bucketAt(T0 + 59.5 * 60_000)).toBe(59)
    expect(w.bucketAt(T0 + 999 * 60_000)).toBe(59)
  })

  it('accumulates traffic up to the cursor and keeps only recent activity for particles', () => {
    const at15 = flowsAt(live, Date.parse(iso(15)))
    expect(at15).toHaveLength(1)
    expect(at15[0]).toMatchObject({ total: 10, recent: 0 })
    const end = flowsAt(live, Date.parse(iso(60)))
    const web = end.find((f) => f.dst === 'web-1')
    expect(web).toMatchObject({ total: 30, recent: 0 })
    const ext = end.find((f) => f.dst === 'ext:8.8.8.8')
    expect(ext).toMatchObject({ total: 2, recent: 2 })
  })

  it('makes busier links thicker and caps the size', () => {
    expect(flowRadius(100)).toBeGreaterThan(flowRadius(10))
    expect(flowRadius(1e9)).toBeLessThanOrEqual(0.3)
    expect(flowParticles(0)).toBe(0)
    expect(flowParticles(1000)).toBeLessThanOrEqual(6)
  })

  it('blinks alerts around their time in replay, and keeps open alerts blinking in live mode', () => {
    expect(alertsAt(live, Date.parse(iso(19))).blinking.size).toBe(0)
    expect(alertsAt(live, Date.parse(iso(20.5))).blinking.get('web-1')).toBe(3)
    expect(alertsAt(live, Date.parse(iso(50))).blinking.size).toBe(0)
    const following = alertsAt(live, Date.parse(iso(60)), { following: true })
    expect(following.blinking.has('web-1')).toBe(true)  // status new: still open
    expect(following.blinking.has('ws-1')).toBe(false)  // closed alert stops blinking
    expect(following.seen.get('ws-1')).toHaveLength(1)
  })

  it('lights red team steps in order', () => {
    const a = defaultAssessment(live)
    expect(stepsAt(a, Date.parse(iso(29))).map((s) => s.phase)).toEqual(['pending', 'pending'])
    expect(stepsAt(a, Date.parse(iso(31))).map((s) => s.phase)).toEqual(['active', 'pending'])
    expect(stepsAt(a, Date.parse(iso(33))).map((s) => s.phase)).toEqual(['done', 'active'])
    expect(stepsAt(a, Date.parse(iso(40))).map((s) => s.phase)).toEqual(['done', 'done'])
  })

  it('merges markers that would overlap and keeps the most important colour', () => {
    const m = clusterMarkers(timelineMarkers(live, defaultAssessment(live)))
    const total = m.reduce((n, c) => n + c.items.length, 0)
    expect(total).toBe(5)
    const steps = m.find((c) => c.items.some((x) => x.kind === 'step'))
    expect(steps.kind).toBe('step')
    expect(steps.at).toBe(iso(30))
    for (let i = 1; i < m.length; i++) expect(m[i].x0 - m[i - 1].x0).toBeGreaterThan(0.008)
  })
})

import { detectionAt, nodeStateAt, purpleScore } from '@/visualization-3d/liveModel'

describe('purple split and status replay', () => {
  const step = (over) => ({ index: 0, started_at: iso(30), finished_at: iso(31), detection: null, ...over })
  const alert = (min, same = true) => ({ first_at: iso(min), same_technique: same, detected_after_seconds: (min - 30) * 60, sources: ['sensor'], rule: 'R' })

  it('reveals a detection only once its alert has fired', () => {
    const s = step({ detection: { verdict: 'detected', alerts: [alert(30.5)] } })
    expect(detectionAt(s, Date.parse(iso(29))).verdict).toBe('pending')
    expect(detectionAt(s, Date.parse(iso(30.2))).verdict).toBe('waiting')
    const d = detectionAt(s, Date.parse(iso(31)))
    expect(d).toMatchObject({ verdict: 'detected', ttd: 30, evidence: ['sensor'] })
  })

  it('separates other-rule detections and misses after the grace period', () => {
    expect(detectionAt(step({ detection: { verdict: 'other_rule', alerts: [alert(30.5, false)] } }), Date.parse(iso(32))).verdict).toBe('other_rule')
    const miss = step({ detection: { verdict: 'missed', alerts: [] } })
    expect(detectionAt(miss, Date.parse(iso(32))).verdict).toBe('waiting')        // within 2 minutes of the step end
    expect(detectionAt(miss, Date.parse(iso(33.5))).verdict).toBe('missed')
    expect(detectionAt(miss, Date.parse(iso(32)), { following: true }).verdict).toBe('missed') // live: server verdict is final
  })

  it('scores started steps only', () => {
    const a = { steps: [step({ detection: { verdict: 'detected', alerts: [alert(30.5)] } }), step({ index: 1, started_at: iso(50), finished_at: iso(51) })] }
    expect(purpleScore(a, Date.parse(iso(40)))).toMatchObject({ started: 1, detected: 1, same: 1, missed: 0, meanTtd: 30 })
  })

  it('replays node status from the recorded history', () => {
    const l = { nodes: [{ key: 'db', state: 'running', name: 'cr-db' }, { key: 'sw', state: 'absent', name: null }],
      status_history: { initial: { '*': 'running' }, changes: [
        { at: iso(10), node: 'db', state: 'stopped' }, { at: iso(20), node: 'db', state: 'running' }, { at: iso(40), node: null, state: 'stopped' }] } }
    const at = (m, k = 'db') => nodeStateAt(l, k, Date.parse(iso(m))).state
    expect([at(5), at(15), at(25), at(45)]).toEqual(['running', 'stopped', 'running', 'stopped'])
    expect(at(45, 'sw')).toBe('absent') // never deployed: lab-wide events do not change it
    expect(nodeStateAt(l, 'db', Date.parse(iso(15)), { following: true }).state).toBe('running')
  })
})

describe('sensor-backed detection score', () => {
  it('counts only detections whose evidence includes sensor events', () => {
    const mk = (i, sources) => ({ index: i, started_at: iso(30 + i), finished_at: iso(30.5 + i),
      detection: { verdict: 'detected', alerts: [{ first_at: iso(30.2 + i), same_technique: true, detected_after_seconds: 12, sources, rule: 'R' }] } })
    const a = { steps: [mk(0, ['platform']), mk(1, ['sensor', 'platform']), mk(2, ['platform'])] }
    expect(purpleScore(a, Date.parse(iso(40)))).toMatchObject({ detected: 3, sensor: 1, same: 3 })
  })
})
