import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api, refreshSession, setAccessToken, setAuthLostHandler } from '@/services/api'

// Local edition: one operator and no login screen. The backend issues the session only to requests made from this
// computer (Host/Origin checks), so the store simply opens or refreshes it.
export const useAuthStore = defineStore('auth', () => {
  const user = ref(null)
  const permissions = ref([])
  const ready = ref(false)
  const sessionLost = ref(false)
  const error = ref(null)
  let refreshTimer = null

  const isAuthenticated = computed(() => !!user.value)
  const permSet = computed(() => new Set(permissions.value))
  // 'a|b' means any of a or b; multiple arguments must all be satisfied; null is always allowed
  const can = (...perms) => perms.every((p) => p == null || String(p).split('|').some((x) => permSet.value.has(x)))
  const roles = computed(() => (user.value?.roles || []).map((r) => r.code))

  function apply(d) {
    setAccessToken(d.access_token)
    user.value = d.user
    permissions.value = d.permissions
    sessionLost.value = false
    error.value = null
    clearTimeout(refreshTimer)
    refreshTimer = setTimeout(() => open(), Math.max(30, d.expires_in - 60) * 1000)
  }

  async function open() {
    try { apply(await refreshSession()) } catch (e) { clear(); error.value = e }
  }

  function clear() {
    clearTimeout(refreshTimer)
    setAccessToken(null)
    user.value = null
    permissions.value = []
    sessionLost.value = true
  }

  async function init() {
    if (ready.value) return
    setAuthLostHandler(() => { clear(); open() })
    await open()
    ready.value = true
  }

  async function reloadMe() {
    const d = await api('/auth/me')
    user.value = d.user
    permissions.value = d.permissions
  }

  return { user, permissions, roles, ready, sessionLost, error, isAuthenticated, can, init, open, reloadMe }
})
