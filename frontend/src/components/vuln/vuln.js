export const STATUS_TONE = { open: 'critical', in_remediation: 'warn', fixed_pending_verification: 'accent', resolved: 'ok', false_positive: 'neutral', risk_accepted: 'medium' }
export const STATUS_LABEL = { open: 'open', in_remediation: 'in remediation', fixed_pending_verification: 'fixed · menunggu verifikasi', resolved: 'resolved (terverifikasi)', false_positive: 'false positive', risk_accepted: 'risk accepted' }
export const JOB_TONE = { queued: 'neutral', running: 'accent', completed: 'ok', failed: 'critical', aborted: 'warn' }
export const TASK_TONE = { open: 'neutral', in_progress: 'accent', done: 'ok', cancelled: 'neutral' }
export const evidenceText = (ev) => Object.entries(ev || {}).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join(' · ')
