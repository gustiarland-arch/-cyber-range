// Shared SOC helpers: severity presentation and the realtime stream.
import { onBeforeUnmount, ref } from 'vue'
import { getAccessToken, refreshSession } from './api'

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
export const SEV_TONE = ['neutral', 'low', 'medium', 'high', 'critical']
export const SEV_COLOR = ['#94a3b8', '#38bdf8', '#facc15', '#fb923c', '#f43f5e']
export const sevName = (n) => SEVERITIES[n] ?? String(n)
export const ALERT_STATUS_TONE = { new: 'critical', acknowledged: 'warn', in_progress: 'accent', resolved: 'ok', false_positive: 'neutral' }
export const INCIDENT_STATUSES = ['open', 'investigating', 'contained', 'eradicated', 'recovered', 'closed']
export const INCIDENT_TONE = { open: 'critical', investigating: 'high', contained: 'warn', eradicated: 'accent', recovered: 'ok', closed: 'neutral' }

// Realtime feed over WebSocket. The access token is sent as the first message, never in the URL.
// Reconnects with backoff; refreshes the session when the server rejects an expired token.
export function useSocStream(onMessage) {
  const state = ref('connecting') // connecting | live | offline | denied
  let ws = null
  let stopped = false
  let delay = 1000
  let timer = null

  async function connect() {
    if (stopped) return
    state.value = 'connecting'
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    ws = new WebSocket(`${proto}://${window.location.host}/api/v1/soc/stream`)
    ws.onopen = () => ws.send(JSON.stringify({ token: getAccessToken() }))
    ws.onmessage = (e) => {
      let m
      try { m = JSON.parse(e.data) } catch { return }
      if (m.type === 'hello') { state.value = 'live'; delay = 1000; return }
      if (m.type === 'ping') return
      if (m.type === 'error' && m.data?.code === 'permission_denied') { state.value = 'denied'; stopped = true; return }
      onMessage(m)
    }
    ws.onclose = async (e) => {
      if (stopped) return
      state.value = 'offline'
      if (e.code === 4401) { try { await refreshSession() } catch { stopped = true; return } }
      if (e.code === 4403) { state.value = 'denied'; return }
      timer = setTimeout(connect, delay)
      delay = Math.min(delay * 2, 30000)
    }
  }
  connect()
  onBeforeUnmount(() => { stopped = true; clearTimeout(timer); ws?.close() })
  return { state }
}

export function saveTextFile(name, text) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  a.download = name
  a.click()
  URL.revokeObjectURL(a.href)
}
