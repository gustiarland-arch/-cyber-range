// Backend returns naive UTC timestamps; mark them as UTC before formatting.
export const asDate = (s) => (s ? new Date(/[zZ]|[+-]\d\d:\d\d$/.test(s) ? s : `${s}Z`) : null)
export const fmtTime = (s) => { const d = asDate(s); return d ? d.toLocaleString() : '—' }
export function ago(s) {
  const d = asDate(s); if (!d) return '—'
  const sec = Math.round((Date.now() - d.getTime()) / 1000)
  if (sec < 60) return `${Math.max(sec, 0)} dtk lalu`
  if (sec < 3600) return `${Math.floor(sec / 60)} mnt lalu`
  if (sec < 86400) return `${Math.floor(sec / 3600)} jam lalu`
  return `${Math.floor(sec / 86400)} hr lalu`
}
export const outcomeTone = (o) => ({ success: 'ok', failure: 'high', denied: 'critical' }[o] || 'neutral')
// Durations in seconds -> short Indonesian text ("4 mnt", "2 jam 5 mnt", "3 hr 4 jam").
export function dur(s) {
  if (s === null || s === undefined) return '—'
  const x = Math.round(s)
  if (x < 60) return `${x} dtk`
  if (x < 3600) return `${Math.floor(x / 60)} mnt`
  if (x < 86400) { const m = Math.floor((x % 3600) / 60); return `${Math.floor(x / 3600)} jam${m ? ` ${m} mnt` : ''}` }
  const h = Math.floor((x % 86400) / 3600); return `${Math.floor(x / 86400)} hr${h ? ` ${h} jam` : ''}`
}
