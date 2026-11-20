// REST client. Access token lives in memory only; refresh token is an httpOnly cookie.
const BASE = '/api/v1'
let accessToken = null
let refreshing = null
let onAuthLost = () => {}

export class ApiError extends Error {
  constructor(status, body) {
    const e = body?.error || {}
    let msg = e.message || `Permintaan gagal (${status})`
    if (e.code === 'validation_error' && Array.isArray(e.details) && e.details.length) {
      const f = e.details.slice(0, 3).map((d) => `${(d.loc || []).filter((x) => x !== 'body').join('.') || 'input'}: ${d.msg}`)
      msg += ` (${f.join('; ')})`
    }
    super(msg)
    this.status = status
    this.code = e.code || 'http_error'
    this.details = e.details
    this.requestId = e.request_id
  }
  get isForbidden() { return this.status === 403 }
  get isNetwork() { return this.status === 0 }
}

export function setAccessToken(t) { accessToken = t }
export const getAccessToken = () => accessToken
export function setAuthLostHandler(fn) { onAuthLost = fn }

async function rawFetch(path, { method = 'GET', body, form, query, headers = {}, raw = false } = {}) {
  const url = new URL(BASE + path, window.location.origin)
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (Array.isArray(v)) v.forEach((x) => url.searchParams.append(k, x))   // repeated params: ?k=a&k=b
      else if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v)
    }
  }
  const h = { 'Accept-Language': 'id', ...headers }
  if (body !== undefined) h['Content-Type'] = 'application/json'
  if (accessToken) h.Authorization = `Bearer ${accessToken}`
  let res
  try {
    // `form` (FormData) is sent as multipart; the browser sets the boundary header itself.
    res = await fetch(url, { method, headers: h, body: form ?? (body !== undefined ? JSON.stringify(body) : undefined), credentials: 'same-origin' })
  } catch {
    throw new ApiError(0, { error: { code: 'network_error', message: 'Tidak dapat menghubungi API CYBER RANGE' } })
  }
  if (raw && res.ok) return res
  if (res.status === 204) return null
  const data = await res.json().catch(() => null)
  if (!res.ok) throw new ApiError(res.status, data)
  return data
}

// Optional local access token (CR_LOCAL_ACCESS_TOKEN). It arrives once in the URL fragment (#cr-token=..., never sent to
// a server), is kept in this browser's localStorage and sent only with POST /auth/local.
const LOCAL_TOKEN_KEY = 'cr_local_token'
const TOKEN_RX = /^[A-Za-z0-9_-]{24,200}$/
export function captureLocalToken() {
  const m = window.location.hash.match(/(?:^#|&)cr-token=([^&]*)/)
  if (!m) return
  setLocalToken(decodeURIComponent(m[1]))
  const rest = window.location.hash.replace(/(?:^#|&)cr-token=[^&]*/, '').replace(/^&/, '')
  window.history.replaceState(null, '', window.location.pathname + window.location.search + (rest ? `#${rest}` : ''))
}
export function setLocalToken(t) {
  try { if (TOKEN_RX.test(t || '')) localStorage.setItem(LOCAL_TOKEN_KEY, t); else localStorage.removeItem(LOCAL_TOKEN_KEY) } catch { /* storage unavailable */ }
}
function localTokenHeaders() {
  try { const t = localStorage.getItem(LOCAL_TOKEN_KEY); return t ? { 'X-Local-Token': t } : {} } catch { return {} }
}

export async function refreshSession() {
  if (!refreshing) {
    // Local edition: reuse the refresh cookie, or open the single operator session (the backend only allows this computer).
    refreshing = rawFetch('/auth/refresh', { method: 'POST' })
      .catch(() => rawFetch('/auth/local', { method: 'POST', headers: localTokenHeaders() }))
      .then((d) => { accessToken = d.access_token; return d })
      .finally(() => { refreshing = null })
  }
  return refreshing
}

export async function api(path, opts = {}) {
  try {
    return await rawFetch(path, opts)
  } catch (e) {
    if (e instanceof ApiError && e.status === 401 && e.code === 'token_expired' && !opts._retried) {
      try {
        await refreshSession()
      } catch {
        accessToken = null
        onAuthLost()
        throw e
      }
      return api(path, { ...opts, _retried: true })
    }
    if (e instanceof ApiError && e.status === 401 && accessToken && path !== '/auth/local') {
      accessToken = null
      onAuthLost()
    }
    throw e
  }
}

export async function download(path, query, filename) {
  const res = await api(path, { query, raw: true })
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

// POST with a JSON body and save the binary response (e.g. evidence download, which requires a recorded reason).
export async function downloadPost(path, body, filename) {
  const res = await api(path, { method: 'POST', body, raw: true })
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}
