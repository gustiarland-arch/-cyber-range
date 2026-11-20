export const STATUS_TONE = {
  pending_approval: 'warn', approved: 'accent', rejected: 'bad', queued: 'accent', running: 'accent', completed: 'ok',
  aborted: 'high', failed: 'bad', expired: 'neutral', cancelled: 'neutral',
}
export const statusLabel = (s) => s.replace('_', ' ')
export const isLive = (s) => ['queued', 'running'].includes(s)
export function localInput(d) { // Date -> value for <input type="datetime-local">
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}
