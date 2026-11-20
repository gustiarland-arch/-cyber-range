// Lab status presentation shared by the lab pages.
export const TRANSITIONAL = ['provisioning', 'stopping', 'starting', 'resetting', 'snapshotting', 'restoring', 'destroying']
export const STATUS_TONE = {
  running: 'ok', stopped: 'neutral', not_deployed: 'neutral', failed: 'bad',
  provisioning: 'accent', stopping: 'warn', starting: 'accent', resetting: 'accent', snapshotting: 'accent', restoring: 'accent', destroying: 'warn',
}
export const STATUS_LABEL = { not_deployed: 'not deployed', running: 'running', stopped: 'stopped', failed: 'gagal', provisioning: 'provisioning', stopping: 'stopping', starting: 'starting', resetting: 'resetting', snapshotting: 'snapshotting', restoring: 'restoring', destroying: 'destroying' }
export const isBusy = (s) => TRANSITIONAL.includes(s)

// Which lifecycle actions the API accepts in each state (mirrors app/cyber_range/service.py).
export function allowedActions(status) {
  return {
    deploy: status === 'not_deployed',
    start: status === 'stopped',
    stop: status === 'running',
    reset: status === 'running' || status === 'stopped',
    snapshot: status === 'running' || status === 'stopped',
    destroy: ['running', 'stopped', 'failed'].includes(status),
    delete: status === 'not_deployed',
  }
}

export function fmtBytes(n) {
  if (n == null) return '—'
  const u = ['B', 'KB', 'MB', 'GB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`
}
