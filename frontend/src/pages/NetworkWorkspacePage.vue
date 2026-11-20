<script setup>
// Network Intelligence Workspace: graf jaringan lab + detail perangkat + terminal + log + kerentanan dalam satu layar.
import { computed, markRaw, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { VueFlow, MarkerType } from '@vue-flow/core'
import { Background } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import '@vue-flow/core/dist/style.css'
import '@vue-flow/core/dist/theme-default.css'
import '@vue-flow/controls/dist/style.css'
import '@vue-flow/minimap/dist/style.css'
import { FileSearch, ListTree, ShieldAlert, SquareTerminal } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import { DEVICES, primaryIp } from '@/network-editor/catalog'
import DeviceNode from '@/network-editor/DeviceNode.vue'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import LabTerminal from '@/terminal/LabTerminal.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const nodeTypes = { device: markRaw(DeviceNode) }

const labs = ref(null)
const lab = ref(null)
const err = ref(null)
const selectedKey = ref(null)
const tab = ref('terminal')
let timer = null

async function loadLabs() {
  try { labs.value = (await api('/labs')).labs } catch (e) { err.value = e; labs.value = [] }
  if (!route.params.id && labs.value?.length) {
    const pick = labs.value.find((l) => l.status === 'running') || labs.value[0]
    router.replace({ name: 'network-workspace', params: { id: pick.id } })
  }
}
async function loadLab() {
  clearTimeout(timer)
  if (!route.params.id) { lab.value = null; return }
  try { lab.value = await api(`/labs/${route.params.id}`); err.value = null } catch (e) { err.value = e; lab.value = null }
  timer = setTimeout(loadLab, 10000)
}
onMounted(() => { loadLabs(); loadLab() })
onBeforeUnmount(() => clearTimeout(timer))
watch(() => route.params.id, () => { selectedKey.value = null; aiSession.value = null; aiMessages.value = []; loadLab() })

const live = computed(() => Object.fromEntries((lab.value?.instance?.containers || []).map((c) => [c.node_key, c])))
const stats = computed(() => lab.value?.instance?.stats?.containers || {})
const nodes = computed(() => lab.value?.topology?.nodes || [])
const flowNodes = computed(() => nodes.value.map((n) => ({
  id: n.key, type: 'device', position: n.position || { x: 0, y: 0 }, draggable: false, connectable: false,
  selected: n.key === selectedKey.value,
  data: { node: n, severity: live.value[n.key] && live.value[n.key].status !== 'running' ? 'warning' : null },
})))
const flowEdges = computed(() => (lab.value?.topology?.links || []).map((l) => ({
  id: l.key, source: l.source, target: l.target, updatable: false,
  animated: !!(live.value[l.source] && live.value[l.target]),
  style: { stroke: '#22d3ee', strokeOpacity: 0.55, strokeWidth: 1.5 }, markerEnd: MarkerType.ArrowClosed,
})))
const selected = computed(() => nodes.value.find((n) => n.key === selectedKey.value) || null)
const selLive = computed(() => (selected.value ? live.value[selected.value.key] : null))
const selIps = computed(() => {
  if (!selected.value) return []
  const ips = new Set((selected.value.interfaces || []).map((i) => i.ip).filter(Boolean))
  for (const ip of Object.values(selLive.value?.addresses || {})) ips.add(ip)
  return [...ips]
})
const operable = computed(() => auth.can('lab.operate') && lab.value && (lab.value.owner_id === auth.user?.id || auth.can('lab.manage')))
const canTerminal = computed(() => auth.can('lab.terminal') && operable.value && lab.value?.status === 'running' && selLive.value?.status === 'running')

// ---- log, kerentanan, event lab untuk perangkat terpilih
const siem = ref(null)
const vulns = ref(null)
async function loadContext() {
  siem.value = null; vulns.value = null
  if (!selected.value || !selIps.value.length) return
  const key = selected.value.key
  if (auth.can('blueteam.alerts.view')) {
    // satu query per IP (bahasa query SIEM menggabungkan token dengan AND), lalu digabung dan diurutkan
    Promise.all(selIps.value.slice(0, 4).map((ip) => api('/soc/events', { query: { q: `ip:${ip}`, page_size: 25, stats: false } })))
      .then((rs) => {
        const seen = new Map()
        for (const r of rs) for (const e of r.items) seen.set(e.id, e)
        siem.value = [...seen.values()].sort((a, b) => (a.occurred_at < b.occurred_at ? 1 : -1)).slice(0, 50)
      }).catch((e) => { siem.value = { error: e.message } })
  }
  if (auth.can('vuln.view')) {
    api('/vuln/findings', { query: { lab_id: lab.value.id, status: 'all', page_size: 200 } })
      .then((r) => { vulns.value = r.items.filter((f) => f.node_key === key || selIps.value.includes(f.ip)) })
      .catch((e) => { vulns.value = { error: e.message } })
  }
}
watch(selectedKey, () => { loadContext(); if (!canTerminal.value && tab.value === 'terminal') tab.value = 'logs' })
const labEvents = computed(() => (lab.value?.events || []).filter((e) => !selected.value || e.message.includes(selected.value.label) || e.message.includes(selected.value.key)).slice(0, 30))

const sevTone = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info' }
const sevLabel = { 4: 'kritis', 3: 'tinggi', 2: 'sedang', 1: 'rendah', 0: 'info' }
</script>

<template>
  <PageHeader section="Cyber Range Lab" title="Network Intelligence Workspace" subtitle="Graf jaringan lab, detail perangkat, terminal terisolasi, log, dan kerentanan dalam satu layar.">
    <select v-if="labs?.length" class="input !w-64" aria-label="Pilih lab" data-test="ws-lab" :value="route.params.id"
      @change="router.push({ name: 'network-workspace', params: { id: $event.target.value } })">
      <option v-for="l in labs" :key="l.id" :value="String(l.id)">{{ l.name }} · {{ $st(l.status) }}</option>
    </select>
  </PageHeader>
  <div v-if="err" class="panel"><CrState kind="error" :message="err.message" @retry="loadLab" /></div>
  <div v-else-if="labs && !labs.length" class="panel"><CrState kind="empty" title="Belum ada lab" message="Buat dan deploy lab di Lab Manager untuk memakai workspace ini." /></div>
  <div v-else-if="!lab" class="panel"><CrState kind="loading" /></div>
  <div v-else class="grid min-h-[calc(100vh-11rem)] gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]" data-test="workspace">
    <div class="flex min-h-0 flex-col gap-4">
      <div class="panel relative h-[44vh] min-h-[320px] overflow-hidden" data-test="ws-graph">
        <VueFlow id="workspace-graph" :nodes="flowNodes" :edges="flowEdges" :node-types="nodeTypes" :nodes-draggable="false" :nodes-connectable="false"
          :elements-selectable="true" fit-view-on-init :min-zoom="0.2" :max-zoom="2" @node-click="({ node }) => (selectedKey = node.id)" @pane-click="selectedKey = null">
          <Background pattern-color="#22395a" :gap="22" />
          <Controls :show-interactive="false" />
          <MiniMap pannable zoomable class="!bg-ink-900" mask-color="rgba(8,15,28,0.7)" :node-color="(n) => (DEVICES[n.data?.node?.type] || DEVICES.server).color" />
        </VueFlow>
        <div class="absolute left-3 top-3 flex items-center gap-2 rounded border border-ink-700 bg-ink-900/90 px-2 py-1 text-[11px]">
          <CrBadge :tone="lab.status === 'running' ? 'ok' : 'neutral'">{{ $st(lab.status) }}</CrBadge>
          <span class="text-ink-400">{{ nodes.length }} perangkat · {{ (lab.topology?.links || []).length }} link · klik node untuk detail</span>
        </div>
      </div>

      <div class="panel flex min-h-[300px] flex-1 flex-col overflow-hidden">
        <div class="flex items-center gap-1 border-b border-ink-700/60 px-2" role="tablist">
          <button v-for="t in [
              { k: 'terminal', label: 'Terminal', icon: SquareTerminal, show: auth.can('lab.terminal') },
              { k: 'logs', label: 'Log SIEM', icon: FileSearch, show: auth.can('blueteam.alerts.view') },
              { k: 'events', label: 'Event lab', icon: ListTree, show: true },
              { k: 'vulns', label: 'Kerentanan', icon: ShieldAlert, show: auth.can('vuln.view') }].filter((x) => x.show)" :key="t.k"
            role="tab" :aria-selected="tab === t.k" :data-tab="t.k"
            :class="['flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs', tab === t.k ? 'border-accent-400 text-ink-100' : 'border-transparent text-ink-400 hover:text-ink-200']"
            @click="tab = t.k"><component :is="t.icon" class="size-3.5" /> {{ t.label }}</button>
          <span class="ml-auto truncate pr-2 text-[11px] text-ink-500">{{ selected ? selected.label : 'Pilih perangkat di graf' }}</span>
        </div>
        <div class="min-h-0 flex-1 overflow-auto" role="tabpanel">
          <template v-if="tab === 'terminal'">
            <LabTerminal v-if="canTerminal" :key="`${lab.id}-${selected.key}`" class="h-full min-h-[260px]" :lab-id="lab.id" :node-key="selected.key" :label="selected.label" />
            <CrState v-else kind="empty" title="Terminal belum tersedia"
              :message="!selected ? 'Pilih perangkat yang berjalan di graf.' : lab.status !== 'running' ? 'Lab tidak sedang berjalan.' : !operable ? 'Anda tidak dapat mengoperasikan lab ini.' : 'Container perangkat ini tidak berjalan atau tidak di-deploy.'" />
          </template>
          <template v-else-if="tab === 'logs'">
            <CrState v-if="!selected" kind="empty" title="Pilih perangkat" message="Log SIEM difilter berdasarkan IP perangkat terpilih." />
            <CrState v-else-if="siem === null" kind="loading" />
            <CrState v-else-if="siem.error" kind="error" :message="siem.error" />
            <CrState v-else-if="!siem.length" kind="empty" title="Tidak ada event" :message="`Belum ada event SIEM untuk ${selIps.join(', ')}.`" />
            <table v-else class="data-table" data-test="ws-logs"><thead><tr><th>Waktu</th><th>Dataset</th><th>Kategori</th><th>Src → Dst</th><th>Pesan</th></tr></thead>
              <tbody><tr v-for="e in siem" :key="e.id"><td class="font-mono text-[11px]" :title="fmtTime(e.occurred_at)">{{ ago(e.occurred_at) }}</td><td class="text-xs">{{ e.dataset }}<CrBadge v-if="e.is_demo" tone="warn" class="ml-1">DEMO</CrBadge></td>
                <td class="font-mono text-xs">{{ e.category }}<span v-if="e.action">/{{ e.action }}</span></td><td class="font-mono text-[11px]">{{ e.src_ip }} → {{ e.dst_ip }}</td><td class="max-w-md truncate text-xs">{{ e.signature || e.message }}</td></tr></tbody></table>
          </template>
          <template v-else-if="tab === 'events'">
            <ol class="divide-y divide-ink-800" data-test="ws-events"><li v-for="e in labEvents" :key="e.id" class="px-3 py-2 text-xs"><CrBadge>{{ $st(e.kind) }}</CrBadge> <span class="text-ink-300">{{ $tr(e.message) }}</span> <span class="float-right font-mono text-[10px] text-ink-500">{{ ago(e.at) }}</span></li></ol>
            <CrState v-if="!labEvents.length" kind="empty" title="Tidak ada event" message="Event lifecycle lab akan muncul di sini." />
          </template>
          <template v-else-if="tab === 'vulns'">
            <CrState v-if="!selected" kind="empty" title="Pilih perangkat" message="Temuan kerentanan difilter berdasarkan IP perangkat." />
            <CrState v-else-if="vulns === null" kind="loading" />
            <CrState v-else-if="vulns.error" kind="error" :message="vulns.error" />
            <CrState v-else-if="!vulns.length" kind="empty" title="Tidak ada temuan" message="Jalankan scan terotorisasi di Vulnerability Management." />
            <table v-else class="data-table" data-test="ws-vulns"><thead><tr><th>Temuan</th><th>Severity</th><th>Status</th><th>Target</th></tr></thead>
              <tbody><tr v-for="f in vulns" :key="f.id" class="cursor-pointer" @click="router.push({ name: 'vulnerabilities', query: { finding: f.id } })"><td class="text-xs text-ink-100">{{ f.vulnerability.title }} <span class="font-mono text-ink-500">{{ f.vulnerability.code }}</span></td>
                <td><CrBadge :tone="sevTone[f.severity]">{{ sevLabel[f.severity] }}</CrBadge></td><td class="text-xs">{{ $st(f.status) }}</td><td class="font-mono text-[11px]">{{ f.ip }}<span v-if="f.port">:{{ f.port }}</span></td></tr></tbody></table>
          </template>
        </div>
      </div>
    </div>

    <div class="flex min-h-0 flex-col gap-4">
      <CrPanel title="Detail perangkat" data-test="ws-device">
        <CrState v-if="!selected" kind="empty" title="Belum ada pilihan" message="Klik perangkat pada graf." />
        <dl v-else class="space-y-1.5 text-xs">
          <div class="flex justify-between"><dt class="text-ink-500">Nama</dt><dd class="text-ink-100">{{ selected.label }}</dd></div>
          <div class="flex justify-between"><dt class="text-ink-500">Tipe</dt><dd>{{ (DEVICES[selected.type] || {}).label || selected.type }}</dd></div>
          <div class="flex justify-between"><dt class="text-ink-500">Zona</dt><dd class="font-mono">{{ selected.zone || '—' }}</dd></div>
          <div class="flex justify-between"><dt class="text-ink-500">IP</dt><dd class="font-mono">{{ selIps.join(', ') || primaryIp(selected) || '—' }}</dd></div>
          <div v-if="selected.properties?.os" class="flex justify-between"><dt class="text-ink-500">OS</dt><dd>{{ selected.properties.os }}</dd></div>
          <div v-if="selected.properties?.services?.length" class="flex justify-between"><dt class="text-ink-500">Layanan</dt><dd class="font-mono">{{ selected.properties.services.map((x) => `${x.port}/${x.proto}`).join(' ') }}</dd></div>
          <div class="flex justify-between"><dt class="text-ink-500">Container</dt><dd><CrBadge v-if="selLive" :tone="selLive.status === 'running' ? 'ok' : 'neutral'">{{ $st(selLive.status) }}</CrBadge><span v-else class="text-ink-500">tidak di-deploy</span></dd></div>
          <div v-if="stats[selected.key]" class="flex justify-between"><dt class="text-ink-500">CPU / memori</dt><dd class="font-mono">{{ stats[selected.key].cpu_pct }}% / {{ Math.round(stats[selected.key].mem_bytes / 1048576) }} MB</dd></div>
          <div v-if="selected.tags?.length" class="flex justify-between"><dt class="text-ink-500">Tag</dt><dd>{{ selected.tags.join(', ') }}</dd></div>
        </dl>
      </CrPanel>

    </div>
  </div>
</template>
