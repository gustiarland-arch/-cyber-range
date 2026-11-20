<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Bell, ChevronsLeft, ChevronsRight, FlaskConical, Gauge, Menu, Search, Settings2, Shield, Siren, Type, UserCircle2, X, Zap, Server } from 'lucide-vue-next'
import { NAV } from '@/services/navigation'
import { useAuthStore } from '@/stores/auth'
import { setLocalToken } from '@/services/api'
import { useUiStore } from '@/stores/ui'
import CommandPalette from '@/components/CommandPalette.vue'
import WorkspaceBar from '@/components/WorkspaceBar.vue'
import CrState from '@/components/ui/CrState.vue'

const auth = useAuthStore()
const tokenInput = ref('')
const tokenTried = ref(false)
async function submitToken() {
  setLocalToken(tokenInput.value.trim())
  tokenInput.value = ''
  await auth.open()
  tokenTried.value = !auth.isAuthenticated
}
const ui = useUiStore()
const route = useRoute()
const router = useRouter()
const notifOpen = ref(false)
const userOpen = ref(false)
const prefOpen = ref(false)
const navGroups = computed(() => NAV.map((g) => ({ ...g, items: g.items.filter((i) => i.to && auth.can(i.perm)) })).filter((g) => g.items.length))

const denied = computed(() => {
  const need = route.meta.perm ? [route.meta.perm].flat() : []
  const missing = need.filter((p) => !auth.can(p))
  return missing.length ? missing : null
})

function onKey(e) {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); ui.paletteOpen = !ui.paletteOpen }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') { e.preventDefault(); ui.toggleSidebar() }
}
function closeMenus(e) {
  if (!e.target.closest('[data-menu]')) { notifOpen.value = false; userOpen.value = false; prefOpen.value = false }
}
onMounted(() => { window.addEventListener('keydown', onKey); window.addEventListener('click', closeMenus) })
onBeforeUnmount(() => { window.removeEventListener('keydown', onKey); window.removeEventListener('click', closeMenus) })

const toneDot = { red: 'bg-red-team', blue: 'bg-blue-team' }
// Phones: the sidebar becomes a drawer and a bottom bar gives the read-only essentials.
const mobileNav = ref(false)
const MOBILE_TABS = [
  { label: 'Ringkasan', to: 'overview', icon: Gauge, perm: 'dashboard.view' },
  { label: 'Alert', to: 'incident-response', icon: Siren, perm: 'blueteam.alerts.view' },
  { label: 'SOAR', to: 'soar', icon: Zap, perm: 'incident.view' },
  { label: 'Lab', to: 'labs', icon: Server, perm: 'lab.view' },
]
router.afterEach(() => { mobileNav.value = false })
</script>

<template>
  <div class="flex h-full">
    <!-- Sidebar -->
    <div v-if="mobileNav" class="fixed inset-0 z-40 bg-black/60 md:hidden" aria-hidden="true" @click="mobileNav = false" />
    <aside :class="['flex-col border-r border-ink-800 bg-ink-900 transition-[width] md:static md:flex md:shrink-0 md:bg-ink-900/90',
                    mobileNav ? 'fixed inset-y-0 left-0 z-50 flex w-72' : 'hidden', ui.sidebarCollapsed ? 'md:w-16' : 'md:w-72']" aria-label="Navigasi utama">
      <div class="flex h-14 items-center gap-2.5 border-b border-ink-800 px-4">
        <div class="grid size-8 place-items-center rounded-md border border-accent-500/40 bg-accent-500/10 shadow-glow"><Shield class="size-4 text-accent-400" /></div>
        <div v-if="!ui.sidebarCollapsed" class="leading-tight">
          <div class="font-mono text-sm font-semibold tracking-[0.25em] text-ink-100">CYBER RANGE</div>
          <div class="text-[10px] uppercase tracking-widest text-ink-500">Edisi Lokal · Simulasi</div>
        </div>
      </div>
      <nav class="flex-1 overflow-y-auto px-2 py-3">
        <div v-for="group in navGroups" :key="group.section" class="mb-4">
          <div v-if="!ui.sidebarCollapsed" class="mb-1 flex items-center gap-2 px-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-500">
            <span v-if="group.tone" :class="['size-1.5 rounded-full', toneDot[group.tone]]" />{{ group.section }}
          </div>
          <template v-for="item in group.items" :key="item.label">
            <RouterLink v-if="item.to && auth.can(item.perm)" :to="{ name: item.to }" :title="item.hint || item.label"
              class="group flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm text-ink-300 transition hover:bg-ink-800 hover:text-ink-100"
              active-class="!bg-accent-500/10 !text-accent-300 ring-1 ring-inset ring-accent-500/30">
              <component :is="item.icon" class="size-4 shrink-0" />
              <span v-if="!ui.sidebarCollapsed" class="truncate">{{ item.label }}</span>
            </RouterLink>
          </template>
        </div>
      </nav>
      <button class="flex h-10 items-center justify-center border-t border-ink-800 text-ink-500 hover:text-ink-200" :aria-label="ui.sidebarCollapsed ? 'Perluas sidebar' : 'Ciutkan sidebar'" title="Buka/tutup sidebar (Ctrl+B)" @click="ui.toggleSidebar()">
        <ChevronsRight v-if="ui.sidebarCollapsed" class="size-4" /><ChevronsLeft v-else class="size-4" />
      </button>
    </aside>

    <!-- Main -->
    <div class="flex min-w-0 flex-1 flex-col">
      <header class="flex h-14 shrink-0 items-center gap-3 border-b border-ink-800 bg-ink-900/60 px-3 backdrop-blur md:px-4">
        <button class="rounded-md p-2 text-ink-300 hover:bg-ink-800 md:hidden" :aria-label="mobileNav ? 'Tutup menu' : 'Buka menu'" data-test="mobile-menu" @click="mobileNav = !mobileNav">
          <X v-if="mobileNav" class="size-5" /><Menu v-else class="size-5" /></button>
        <button class="flex h-9 w-full max-w-md items-center gap-2 rounded-md border border-ink-700 bg-ink-850 px-3 text-sm text-ink-500 hover:border-ink-600" @click="ui.paletteOpen = true">
          <Search class="size-4" /><span class="flex-1 truncate text-left">Cari modul dan aksi…</span>
          <kbd class="hidden rounded md:inline border border-ink-600 px-1.5 font-mono text-[10px] text-ink-400">Ctrl K</kbd>
        </button>
        <div class="ml-auto flex items-center gap-2">
          <span class="hidden items-center gap-1.5 rounded border border-warn/40 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-warn lg:flex" title="Semua lab terisolasi dan semua data contoh berlabel DEMO"><FlaskConical class="size-3" /> Lingkungan simulasi</span>
          <span class="hidden items-center gap-1.5 rounded border border-ink-700 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-ink-400 md:flex">UTC {{ new Date().toISOString().slice(0, 10) }}</span>
          <div class="relative" data-menu>
            <button class="rounded-md p-2 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Tampilan" title="Tampilan" data-test="pref-menu" @click="prefOpen = !prefOpen; notifOpen = false; userOpen = false">
              <Settings2 class="size-4" /></button>
            <div v-if="prefOpen" class="panel absolute right-0 z-40 mt-2 w-64 p-1 shadow-2xl">
              <button class="flex w-full items-center gap-2 rounded px-3 py-2 text-left text-sm hover:bg-ink-800" role="menuitemcheckbox" :aria-checked="ui.largeText" data-test="large-text" @click="ui.toggleLargeText()">
                <Type class="size-4" /><span class="flex-1">Teks lebih besar</span><span class="font-mono text-[10px]">{{ ui.largeText ? 'ON' : 'OFF' }}</span></button>
            </div>
          </div>
          <div class="relative" data-menu>
            <button class="relative rounded-md p-2 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Notifikasi" @click="notifOpen = !notifOpen; userOpen = false">
              <Bell class="size-4" />
              <span v-if="ui.notifications.length" class="absolute top-1 right-1 size-2 rounded-full bg-accent-400" />
            </button>
            <div v-if="notifOpen" class="panel absolute right-0 z-40 mt-2 w-80 p-2 shadow-2xl">
              <div class="flex items-center justify-between px-2 py-1">
                <div class="panel-title">Notifikasi</div>
                <button v-if="ui.notifications.length" class="text-xs text-ink-400 hover:text-ink-100" @click="ui.notifications = []">Bersihkan</button>
              </div>
              <div v-if="!ui.notifications.length" class="px-2 py-6 text-center text-xs text-ink-500">Tidak ada notifikasi di sesi ini</div>
              <div v-for="n in ui.notifications" :key="n.id" class="rounded px-2 py-1.5 text-xs hover:bg-ink-800">
                <div :class="n.type === 'error' ? 'text-sev-critical' : n.type === 'success' ? 'text-ok' : 'text-ink-200'">{{ n.message }}</div>
                <div class="font-mono text-[10px] text-ink-500">{{ n.at.toLocaleTimeString() }}</div>
              </div>
            </div>
          </div>
          <div class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm" data-test="operator" title="Satu operator lokal. Tidak ada login: aplikasi hanya melayani komputer ini.">
            <UserCircle2 class="size-5 text-ink-400" />
            <span class="hidden text-left leading-tight sm:block">
              <span class="block text-ink-100">{{ auth.user?.full_name || auth.user?.username }}</span>
              <span class="block font-mono text-[10px] text-ink-500">LOCAL · SIMULASI</span>
            </span>
          </div>
        </div>
      </header>
      <div class="hidden md:block"><WorkspaceBar /></div>
      <main class="min-h-0 flex-1 overflow-y-auto p-3 pb-20 md:p-5 md:pb-5 lg:p-6">
        <div v-if="!auth.isAuthenticated && auth.error?.code === 'local_token_required'" class="panel mx-auto max-w-lg p-5" data-test="local-token">
          <h2 class="text-sm font-semibold text-ink-100">Token akses lokal diperlukan</h2>
          <p class="mt-1 text-xs text-ink-400">Instalasi ini mengaktifkan <span class="font-mono">CR_LOCAL_ACCESS_TOKEN</span>. Buka aplikasi lewat start.bat, atau tempel nilai token dari file <span class="font-mono">.env</span>. Token disimpan di browser ini saja.</p>
          <form class="mt-3 flex gap-2" @submit.prevent="submitToken"><input v-model="tokenInput" type="password" autocomplete="off" class="min-w-0 flex-1 rounded border border-ink-700 bg-ink-850 px-2 py-1.5 font-mono text-xs text-ink-100" placeholder="token" aria-label="Token akses lokal" />
            <button class="rounded bg-accent-500 px-3 text-xs font-medium text-ink-950" type="submit">Buka</button></form>
          <p v-if="tokenTried" class="mt-2 text-xs text-sev-critical">Token tidak cocok.</p>
        </div>
        <div v-else-if="!auth.isAuthenticated" class="panel" data-test="session-error"><CrState kind="error" message="Sesi operator lokal tidak bisa dibuka. Buka aplikasi lewat http://localhost dari komputer yang menjalankannya." @retry="auth.open()" /></div>
        <div v-else-if="denied" class="panel"><CrState kind="denied" message="Modul ini tidak tersedia." :missing="denied" /></div>
        <RouterView v-else />
      </main>
    </div>
    <nav class="fixed inset-x-0 bottom-0 z-30 grid grid-cols-4 border-t border-ink-800 bg-ink-900/95 backdrop-blur md:hidden" aria-label="Navigasi ponsel" data-test="mobile-tabs">
      <template v-for="t in MOBILE_TABS" :key="t.to">
        <RouterLink v-if="auth.can(t.perm)" :to="{ name: t.to }" class="flex flex-col items-center gap-0.5 py-2 text-[10px] text-ink-400" active-class="!text-accent-300">
          <component :is="t.icon" class="size-5" />{{ t.label }}</RouterLink>
        <span v-else class="flex flex-col items-center gap-0.5 py-2 text-[10px] text-ink-700" aria-disabled="true"><component :is="t.icon" class="size-5" />{{ t.label }}</span>
      </template>
    </nav>
    <CommandPalette />
  </div>
</template>
