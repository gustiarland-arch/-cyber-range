// Client for GET /labs/{id}/live/stream (server-sent events). EventSource cannot send the Authorization header, so the
// stream is read with fetch. The stream carries no data: on `changed` the caller refetches /live (permissions and IP
// scoping are applied there). Reconnects with backoff; if streaming keeps failing, `onFallback(true)` tells the caller
// to poll instead.
import { getAccessToken, refreshSession } from './api'

export function openLiveStream(labId, { onChange, onState = () => {}, onFallback = () => {} } = {}) {
  let stopped = false, ctrl = null, failures = 0, timer = null

  async function connect() {
    if (stopped) return
    ctrl = new AbortController()
    try {
      let res = await fetch(`/api/v1/labs/${labId}/live/stream`, { headers: { Authorization: `Bearer ${getAccessToken()}`, Accept: 'text/event-stream' }, signal: ctrl.signal, credentials: 'same-origin' })
      if (res.status === 401) {
        await refreshSession()
        res = await fetch(`/api/v1/labs/${labId}/live/stream`, { headers: { Authorization: `Bearer ${getAccessToken()}`, Accept: 'text/event-stream' }, signal: ctrl.signal, credentials: 'same-origin' })
      }
      if (!res.ok || !res.body) throw new Error(`stream ${res.status}`)
      failures = 0
      onFallback(false)
      onState('live')
      const reader = res.body.getReader()
      const dec = new TextDecoder()
      let buf = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buf += dec.decode(value, { stream: true })
        let i
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const msg = buf.slice(0, i)
          buf = buf.slice(i + 2)
          if (/^event: changed$/m.test(msg)) onChange()
        }
      }
    } catch (e) {
      if (stopped || e?.name === 'AbortError') return
      failures++
    }
    if (stopped) return
    onState('reconnecting')
    if (failures >= 3) onFallback(true)
    timer = setTimeout(connect, Math.min(30_000, 1000 * 2 ** Math.min(failures, 5)))
  }

  connect()
  return () => { stopped = true; clearTimeout(timer); ctrl?.abort() }
}
