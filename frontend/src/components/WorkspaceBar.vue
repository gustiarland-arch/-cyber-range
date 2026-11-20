<script setup>
// Breadcrumbs + workspace tabs (halaman yang terakhir dibuka, disimpan per browser).
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ChevronRight, X } from 'lucide-vue-next'
import { NAV } from '@/services/navigation'

const route = useRoute()
const router = useRouter()
const PARENT = { 'incident-detail': 'incident-response', assessment: 'attack-simulation', 'network-editor': 'networks', 'network-3d': 'network-3d-list',
  'lab-detail': 'labs', 'malware-sample': 'malware', case: 'cases', evidence: 'forensics', 'ctf-challenge': 'ctf', course: 'training', mission: 'missions' }
const byName = {}
for (const g of NAV) for (const it of g.items) byName[it.to] = { section: g.section, label: it.label }

const crumbs = computed(() => {
  const name = route.name
  if (!name || name === 'not-found') return []
  const parent = PARENT[name]
  const top = byName[parent || name]
  const out = []
  if (top) out.push({ label: top.section })
  if (parent && top) out.push({ label: top.label, to: { name: parent } })
  out.push({ label: parent ? `${route.meta.title || name}${route.params.id ? ' #' + route.params.id : ''}` : (top?.label || route.meta.title || name) })
  return out
})

const KEY = 'cr.workspaceTabs'
const MAX = 8
function readTabs() { try { return JSON.parse(localStorage.getItem(KEY) || '[]') } catch { return [] } }
const tabs = ref(readTabs())
function save() { try { localStorage.setItem(KEY, JSON.stringify(tabs.value)) } catch { /* storage unavailable */ } }
watch(() => route.fullPath, () => {
  if (!route.name || ['login', 'not-found'].includes(route.name)) return
  const title = crumbs.value.at(-1)?.label || route.meta.title || String(route.name)
  const i = tabs.value.findIndex((t) => t.path === route.fullPath || (t.name === route.name && JSON.stringify(t.params) === JSON.stringify(route.params)))
  if (i >= 0) tabs.value[i] = { ...tabs.value[i], path: route.fullPath, title }
  else { tabs.value.push({ path: route.fullPath, name: route.name, params: { ...route.params }, title }); if (tabs.value.length > MAX) tabs.value.shift() }
  save()
}, { immediate: true })
function close(t) {
  const i = tabs.value.indexOf(t)
  tabs.value.splice(i, 1); save()
  if (t.path === route.fullPath) router.push(tabs.value[Math.max(0, i - 1)]?.path || { name: 'overview' })
}
const isActive = (t) => t.path === route.fullPath
</script>
<template>
  <div class="flex shrink-0 flex-col border-b border-ink-800 bg-ink-900/40">
    <div v-if="tabs.length > 1" class="flex items-end gap-1 overflow-x-auto px-3 pt-1.5" role="tablist" aria-label="Tab workspace" data-test="workspace-tabs">
      <div v-for="t in tabs" :key="t.path" role="tab" :aria-selected="isActive(t)"
        :class="['group flex max-w-[14rem] shrink-0 items-center gap-1 rounded-t-md border border-b-0 px-2.5 py-1 text-xs', isActive(t) ? 'border-ink-700 bg-ink-950 text-ink-100' : 'border-transparent text-ink-400 hover:bg-ink-850 hover:text-ink-200']">
        <RouterLink :to="t.path" class="truncate">{{ t.title }}</RouterLink>
        <button class="rounded p-0.5 opacity-60 hover:bg-ink-800 hover:opacity-100" :aria-label="`Tutup tab ${t.title}`" @click="close(t)"><X class="size-3" /></button>
      </div>
    </div>
    <nav v-if="crumbs.length" aria-label="Navigasi breadcrumb" class="flex items-center gap-1 px-5 py-1.5 text-[11px] text-ink-500 lg:px-6" data-test="breadcrumbs">
      <template v-for="(c, i) in crumbs" :key="i">
        <ChevronRight v-if="i" class="size-3" />
        <RouterLink v-if="c.to" :to="c.to" class="hover:text-ink-200">{{ c.label }}</RouterLink>
        <span v-else :class="i === crumbs.length - 1 ? 'text-ink-300' : ''" :aria-current="i === crumbs.length - 1 ? 'page' : undefined">{{ c.label }}</span>
      </template>
    </nav>
  </div>
</template>
