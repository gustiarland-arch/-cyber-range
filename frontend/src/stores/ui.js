import { defineStore } from 'pinia'
import { ref } from 'vue'

let nextId = 1

// Per-browser display preferences. Storage can be unavailable (private mode, blocked site data): never fail on it.
function readPref(key, fallback) { try { const v = localStorage.getItem(key); return v === null ? fallback : v === '1' } catch { return fallback } }
function writePref(key, on) { try { localStorage.setItem(key, on ? '1' : '0') } catch { /* preference only */ } }

export const useUiStore = defineStore('ui', () => {
  const toasts = ref([])
  const paletteOpen = ref(false)
  const sidebarCollapsed = ref(readPref('cr.sidebar', false))
  const notifications = ref([])
  const largeText = ref(readPref('cr.largeText', false))
  const applyText = () => document.documentElement.classList.toggle('text-large', largeText.value)
  applyText()

  function toast(message, type = 'info', timeout = 4000) {
    const id = nextId++
    toasts.value.push({ id, message, type })
    notifications.value.unshift({ id, message, type, at: new Date() })
    notifications.value = notifications.value.slice(0, 30)
    if (timeout) setTimeout(() => dismiss(id), timeout)
  }
  const success = (m) => toast(m, 'success')
  const error = (e) => toast(typeof e === 'string' ? e : `${e.message}${e.requestId ? ` · ref ${e.requestId.slice(0, 8)}` : ''}`, 'error', 7000)
  const dismiss = (id) => { toasts.value = toasts.value.filter((t) => t.id !== id) }
  function toggleSidebar() { sidebarCollapsed.value = !sidebarCollapsed.value; writePref('cr.sidebar', sidebarCollapsed.value) }
  function toggleLargeText() { largeText.value = !largeText.value; writePref('cr.largeText', largeText.value); applyText() }
  return { toasts, notifications, paletteOpen, sidebarCollapsed, largeText, toast, success, error, dismiss, toggleSidebar,
    toggleLargeText }
})
