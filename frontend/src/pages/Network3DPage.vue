<script setup>
// 3D view in two modes:
//   mode="network"  saved topology (read-only design view), as before
//   mode="lab"      a deployed lab, driven by GET /labs/{id}/live: node status and IPs, real sensor traffic,
//                   red team steps and alerts, with a replay timeline over the selected window
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Activity, ArrowLeft, ChevronsLeft, ChevronsRight, Columns3, Crosshair, Pause, Pencil, Play, Radar, Radio, RotateCcw, ScanEye, Shield, SquareTerminal, Swords, Tags, Waves, X } from 'lucide-vue-next'
import { api } from '@/services/api'
import { openLiveStream } from '@/services/liveStream'
import { ago, fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { DEVICES } from '@/network-editor/catalog'
import { fmtBytes } from '@/components/labs/labStatus'
import { SEV_COLOR, STATE_COLOR, STATE_LABEL, VERDICT_LABEL, VERDICT_TONE, alertsAt, clusterMarkers, defaultAssessment, detectionAt, externalNodes, flowsAt, nodeStateAt, purpleScore, stepsAt, timelineMarkers, windowOf } from '@/visualization-3d/liveModel'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrState from '@/components/ui/CrState.vue'
import SevBadge from '@/components/soc/SevBadge.vue'
import LabTerminal from '@/terminal/LabTerminal.vue'

const props = defineProps({ mode: { type: String, default: 'network' } })
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const isLab = computed(() => props.mode === 'lab')

const el = ref(null)
const err = ref(null)
const net = ref(null)          // network mode: /networks/{id}
const live = ref(null)         // lab mode: /labs/{id}/live
const labsOfNet = ref([])
const selectedKey = ref(null)
const flow = ref(false)
const labels = ref(true)
const scene = shallowRef(null)
const minutes = ref(Number(route.query.minutes) || 60)
const following = ref(true)    // cursor pinned to "now" and refreshed by polling
const playing = ref(false)
const cursor = ref(0)
const assessmentId = ref(null)
const tab = ref('info')
const termNode = ref(null)
const events = ref({ loading: false, items: [], error: null })
const split = ref(route.query.split !== '0') // Red | Blue side by side (lab mode with an assessment)
const hoverStep = ref(null)
const sensors = ref({ sensors: [], images: {} })
const sensorOpen = ref(false)
const sensorBusy = ref(false)
const sensorErr = ref(null)
const streamState = ref('connecting') // live | reconnecting | polling
const redOpen = ref(true)
const blueOpen = ref(true)
const narrow = ref(false) // canvas narrower than 1400 px: panels start collapsed
const flowLimit = ref(60) // busiest links drawn in 3D (0 = all); the node panel always lists every connection
let poll = null, player = null, lastKey = '', closeStream = null, refetchTimer = null, lastFetch = 0

const doc = computed(() => (isLab.value ? live.value?.topology : net.value?.topology))

async function load() {
  err.value = null
  try {
    if (isLab.value) await refreshLive(true)
    else {
      net.value = await api(`/networks/${route.params.id}`)
      await mountScene(net.value.topology, net.value.issues)
      try { labsOfNet.value = (await api('/labs')).labs.filter((l) => l.network_id === net.value.id && l.status !== 'not_deployed') } catch { labsOfNet.value = [] }
    }
  } catch (e) { err.value = e }
}

async function mountScene(topology, issues = []) {
  await nextTick()
  const { NetworkScene } = await import('@/visualization-3d/NetworkScene.js')
  scene.value?.dispose()
  scene.value = new NetworkScene(el.value, { onSelect: (k) => { selectedKey.value = k } })
  scene.value.build(topology, issues)
  window.__cr3d = scene.value // test hook: read-only summary via __cr3d.snapshot()
}

async function refreshLive(first = false) {
  const data = await api(`/labs/${route.params.id}/live`, { query: { minutes: minutes.value } })
  const rebuild = first || !live.value || JSON.stringify(live.value.topology) !== JSON.stringify(data.topology)
  live.value = data
  if (rebuild) await mountScene(data.topology)
  if (!assessmentId.value || !data.assessments.some((a) => a.id === assessmentId.value)) assessmentId.value = defaultAssessment(data)?.id ?? null
  if (following.value) cursor.value = windowOf(data).end
  lastKey = ''
  render()
}

const win = computed(() => (live.value ? windowOf(live.value) : null))
const assessment = computed(() => live.value?.assessments.find((a) => a.id === assessmentId.value) || null)
const steps = computed(() => (live.value ? stepsAt(assessment.value, cursor.value) : []))
const alertState = computed(() => (live.value ? alertsAt(live.value, cursor.value, { following: following.value }) : { blinking: new Map(), seen: new Map() }))
const markers = computed(() => (live.value ? clusterMarkers(timelineMarkers(live.value, assessment.value)) : []))
const liveNodes = computed(() => new Map((live.value?.nodes || []).map((n) => [n.key, n])))
// node state at the cursor: current state when following, otherwise replayed from the lab's recorded state changes
const nodeStates = computed(() => new Map((live.value?.nodes || []).map((n) => [n.key, nodeStateAt(live.value, n.key, cursor.value, { following: following.value }).state])))
const counts = computed(() => {
  const c = { running: 0, pending: 0, stopped: 0, error: 0, absent: 0 }
  for (const s of nodeStates.value.values()) c[s]++
  return c
})

const allFlowsNow = computed(() => (live.value ? flowsAt(live.value, cursor.value) : []))
function frame() {
  const all = allFlowsNow.value
  const flows = flowLimit.value && all.length > flowLimit.value ? [...all].sort((a, b) => b.total - a.total).slice(0, flowLimit.value) : all
  return {
    nodes: new Map(live.value.nodes.map((n) => [n.key, { state: nodeStates.value.get(n.key) || n.state, ips: Object.values(n.ips), planned: n.ips_planned }])),
    external: externalNodes(live.value),
    flows,
    blinking: alertState.value.blinking,
    seen: alertState.value.seen,
    attack: assessment.value ? { attacker: assessment.value.attacker_node, steps: steps.value } : null,
  }
}

function render(force = false) {
  if (!scene.value || !live.value) return
  // Rebuilding tubes is not free: only re-apply when something visible changes (bucket, step phases, blinking set).
  const key = [flowLimit.value, following.value, [...nodeStates.value.values()].join(''), win.value.bucketAt(cursor.value), steps.value.map((s) => s.phase).join(''), [...alertState.value.blinking.keys()].join(','), live.value.generated_at].join('|')
  if (!force && key === lastKey) return
  lastKey = key
  scene.value.applyLive(frame())
}
watch([cursor, assessmentId, flowLimit], () => render())

// ------------------------------------------------------------ timeline
function goLive() {
  following.value = true
  playing.value = false
  stopPlayer()
  refreshLive().catch((e) => { err.value = e })
}
function togglePlay() {
  if (playing.value) { playing.value = false; stopPlayer(); return }
  following.value = false
  playing.value = true
  if (cursor.value >= win.value.end - win.value.size) cursor.value = win.value.start
  const step = (win.value.end - win.value.start) / 300 // whole window in ~30 s
  player = setInterval(() => {
    cursor.value = Math.min(win.value.end, cursor.value + step)
    if (cursor.value >= win.value.end) { playing.value = false; stopPlayer() }
  }, 100)
}
function stopPlayer() { clearInterval(player); player = null }
function scrub(e) {
  following.value = false
  playing.value = false
  stopPlayer()
  cursor.value = Number(e.target.value)
}
function jump(m) {
  following.value = false
  cursor.value = Date.parse(m.at) + 1
}
watch(minutes, () => { router.replace({ query: { ...route.query, minutes: minutes.value } }); following.value = true; refreshLive().catch((e) => { err.value = e }) })

// ------------------------------------------------------------ selection panel
const node = computed(() => doc.value?.nodes.find((n) => n.key === selectedKey.value) || null)
const extSel = computed(() => (selectedKey.value?.startsWith('ext:') ? selectedKey.value.slice(4) : null))
const lnode = computed(() => liveNodes.value.get(selectedKey.value) || null)
const nodeIps = computed(() => (lnode.value ? Object.values(lnode.value.ips) : (node.value?.interfaces || []).map((i) => i.ip).filter(Boolean)))
const zoneName = (k) => doc.value?.zones.find((z) => z.key === k)?.name || '—'
const subnet = (k) => doc.value?.subnets.find((s) => s.key === k)
const neighbors = computed(() => {
  if (!node.value) return []
  return doc.value.links.filter((l) => l.source === node.value.key || l.target === node.value.key).map((l) => {
    const other = doc.value.nodes.find((n) => n.key === (l.source === node.value.key ? l.target : l.source))
    return { link: l, node: other }
  })
})
const nodeIssues = computed(() => (net.value?.issues || []).filter((i) => i.ref?.node === selectedKey.value))
const nodeFlows = computed(() => (live.value ? flowsAt(live.value, cursor.value).filter((f) => f.src === selectedKey.value || f.dst === selectedKey.value) : []))
const nodeAlerts = computed(() => (live.value?.alerts || []).filter((a) => a.nodes.some((n) => n.key === selectedKey.value))
  .map((a) => ({ ...a, roles: a.nodes.find((n) => n.key === selectedKey.value).roles })))
const label = (k) => (k?.startsWith('ext:') ? k.slice(4) : liveNodes.value.get(k)?.label || doc.value?.nodes.find((n) => n.key === k)?.label || k)
const canTerminal = computed(() => isLab.value && live.value?.access.terminal && live.value?.instance?.status === 'running'
  && lnode.value?.backing === 'container' && lnode.value?.state === 'running')

function choose(k) { selectedKey.value = k; scene.value?.select(k) }
function focusNode(k = selectedKey.value) { if (k) scene.value?.focus(k) }
function toggleFlow() { flow.value = !flow.value; scene.value?.setFlow(flow.value) }
function toggleLabels() { labels.value = !labels.value; scene.value?.setLabels(labels.value) }
function openSiem() { router.push({ name: 'siem', query: { q: nodeIps.value.map((ip) => `ip:${ip}`)[0] || '', range: minutes.value <= 60 ? '1h' : '24h' } }) }

async function loadEvents() {
  if (!live.value || !nodeIps.value.length) { events.value = { loading: false, items: [], error: null }; return }
  events.value = { loading: true, items: [], error: null }
  try {
    const res = await Promise.all(nodeIps.value.slice(0, 3).map((ip) => api('/soc/events', { query: { q: `ip:${ip}`, from: live.value.window.start, page_size: 30, stats: false } })))
    const seen = new Set()
    const items = res.flatMap((r) => r.items).filter((e) => !seen.has(e.id) && seen.add(e.id)).sort((a, b) => (a.occurred_at < b.occurred_at ? 1 : -1)).slice(0, 40)
    events.value = { loading: false, items, error: null }
  } catch (e) { events.value = { loading: false, items: [], error: e } }
}
watch([selectedKey, tab], () => { if (tab.value === 'events') loadEvents() })
watch(selectedKey, (k) => { if (!k) tab.value = 'info' })

// ------------------------------------------------------------ purple team split
const showSplit = computed(() => isLab.value && split.value && !!assessment.value)
const blueRows = computed(() => steps.value.map((s) => ({ step: s, det: detectionAt(s, cursor.value, { following: following.value }) })))
const score = computed(() => purpleScore(assessment.value, cursor.value, { following: following.value }))
const alertFeed = computed(() => (live.value?.alerts || []).filter((a) => Date.parse(a.first_seen) <= cursor.value)
  .sort((a, b) => (a.first_seen < b.first_seen ? 1 : -1)).slice(0, 12))
const fmtTtd = (x) => (x == null ? '—' : x < 1 ? '< 1 dtk' : x < 60 ? `${x.toFixed(1)} dtk` : `${(x / 60).toFixed(1)} mnt`)
const PANEL_PX = 344 // w-80 + margin
const COLLAPSED_PX = 48
function applyInsets() {
  if (!scene.value) return
  if (!showSplit.value) { scene.value.setInsets({}); return }
  const rightPanel = blueOpen.value || !!node.value || !!extSel.value // the node panel opens over the Blue side
  scene.value.setInsets({ left: redOpen.value ? PANEL_PX : COLLAPSED_PX, right: rightPanel ? PANEL_PX : COLLAPSED_PX })
}
watch([showSplit, redOpen, blueOpen, scene, selectedKey], () => nextTick(applyInsets))
let sizeObs = null
function watchWidth() {
  if (!el.value || sizeObs) return
  sizeObs = new ResizeObserver(([e]) => {
    const isNarrow = e.contentRect.width < 1400
    if (isNarrow !== narrow.value) { narrow.value = isNarrow; redOpen.value = blueOpen.value = !isNarrow }
  })
  sizeObs.observe(el.value)
}
// run an approved assessment from here, so it can be watched from its first step
const runArm = ref(false)
const runBusy = ref(false)
const runErr = ref(null)
const canRun = computed(() => assessment.value?.status === 'approved' && auth.can('redteam.assessment.execute') && live.value?.instance?.status === 'running')
async function runAssessment() {
  if (!runArm.value) { runArm.value = true; return }
  runBusy.value = true
  runErr.value = null
  try {
    await api(`/redteam/assessments/${assessment.value.id}/execute`, { method: 'POST' })
    runArm.value = false
    following.value = true
    await refreshLive()
  } catch (e) { runErr.value = e } finally { runBusy.value = false }
}
watch(assessmentId, () => { runArm.value = false; runErr.value = null })
function toggleSplit() { split.value = !split.value; router.replace({ query: { ...route.query, split: split.value ? undefined : '0' } }) }

// ------------------------------------------------------------ sensors
async function loadSensors() {
  try { sensors.value = await api(`/labs/${route.params.id}/sensors`) } catch { sensors.value = { sensors: [], images: {} } }
}
const activeSensors = computed(() => sensors.value.sensors.filter((x) => ['running', 'starting', 'pending'].includes(x.status)))
const failedSensors = computed(() => sensors.value.sensors.filter((x) => x.status === 'failed'))
// the same failure (e.g. an image that cannot be pulled) is shown once, with the sensors it affects
const sensorErrors = computed(() => {
  const m = new Map()
  for (const x of sensors.value.sensors.filter((y) => y.error)) {
    const key = x.error.replace(/\b(s|subnet)-[\w-]+/g, '').slice(0, 400)
    const e = m.get(key) || { text: x.error, who: [] }
    e.who.push(`${x.kind} ${x.subnet_key}`)
    m.set(key, e)
  }
  return [...m.values()]
})
const canAttachSensors = computed(() => live.value?.access.operate && live.value?.instance?.status === 'running')
async function attachSensors() {
  sensorBusy.value = true
  sensorErr.value = null
  try {
    await api(`/labs/${route.params.id}/sensors`, { method: 'POST', body: { kinds: ['zeek', 'suricata'] } })
    await loadSensors()
  } catch (e) { sensorErr.value = e } finally { sensorBusy.value = false }
}

// ------------------------------------------------------------ real-time updates
function scheduleRefetch() {
  if (!following.value || document.hidden) return
  const wait = Math.max(0, 1500 - (Date.now() - lastFetch)) // at most one refetch per 1.5 s however busy the SIEM is
  clearTimeout(refetchTimer)
  refetchTimer = setTimeout(() => { lastFetch = Date.now(); refreshLive().catch(() => {}); loadSensors() }, wait)
}

onMounted(async () => {
  await load()
  if (!isLab.value) return
  watchWidth()
  loadSensors()
  closeStream = openLiveStream(route.params.id, {
    onChange: scheduleRefetch,
    onState: (s) => { streamState.value = s },
    onFallback: (on) => {
      clearInterval(poll)
      poll = null
      if (on) { streamState.value = 'polling'; poll = setInterval(scheduleRefetch, 15000) }
    },
  })
})
onBeforeUnmount(() => { sizeObs?.disconnect(); closeStream?.(); clearInterval(poll); clearTimeout(refetchTimer); stopPlayer(); scene.value?.dispose(); if (window.__cr3d === scene.value) delete window.__cr3d })

const cursorPct = computed(() => (win.value ? ((cursor.value - win.value.start) / (win.value.end - win.value.start)) * 100 : 100))
const markerColor = (m) => (m.kind === 'step' ? '#ff3b5c' : m.kind === 'alert' ? SEV_COLOR[m.severity] : m.kind === 'lab-error' ? '#f43f5e' : '#94a3b8')
const markerTitle = (m) => m.items.map((x) => `${fmtTime(x.at)} · ${x.label}`).join('\n')
const phaseTone = { active: 'critical', done: 'neutral', pending: 'neutral' }
const fmtClock = (t) => new Date(t).toLocaleTimeString()
</script>

<template>
  <div v-if="err" class="panel"><CrState :kind="err.status === 404 ? 'empty' : 'error'" :title="err.status === 404 ? (isLab ? 'Lab tidak ditemukan' : 'Jaringan tidak ditemukan') : undefined" :message="err.message" @retry="load" /></div>
  <div v-else class="-m-5 flex h-[calc(100%+2.5rem)] flex-col lg:-m-6 lg:h-[calc(100%+3rem)]">
    <!-- toolbar -->
    <div class="flex flex-wrap items-center gap-2 border-b border-ink-800 bg-ink-900/80 px-3 py-2">
      <RouterLink :to="isLab ? { name: 'lab-detail', params: { id: route.params.id } } : { name: 'network-3d-list' }" class="rounded p-1.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Kembali"><ArrowLeft class="size-4" /></RouterLink>
      <div v-if="isLab" class="mr-2"><div class="text-sm font-semibold text-ink-100">{{ live?.lab.name || 'Memuat…' }}</div>
        <div class="font-mono text-[10px] text-ink-500" data-test="live-summary">3D · lab hidup · {{ live?.instance?.status || 'not deployed' }} ·
          <span :style="{ color: STATE_COLOR.running }">{{ counts.running }} berjalan</span> ·
          <span :style="{ color: STATE_COLOR.stopped }">{{ counts.stopped }} mati</span> ·
          <span :style="{ color: STATE_COLOR.error }">{{ counts.error }} error</span> ·
          {{ live?.traffic.total_events ?? 0 }} event sensor · {{ live?.alerts.length ?? 0 }} alert</div></div>
      <div v-else class="mr-2"><div class="text-sm font-semibold text-ink-100">{{ net?.name || 'Memuat…' }}</div>
        <div class="font-mono text-[10px] text-ink-500">3D · desain (read-only) · v{{ net?.version }} · {{ net?.node_count }} perangkat · {{ net?.link_count }} links</div></div>
      <div class="ml-auto flex flex-wrap items-center gap-1.5">
        <template v-if="!isLab && labsOfNet.length">
          <RouterLink v-for="l in labsOfNet" :key="l.id" :to="{ name: 'lab-3d', params: { id: l.id } }" data-test="open-live-lab"
            class="inline-flex h-8 items-center gap-1.5 rounded-md border border-ok/40 bg-ok/10 px-2.5 text-xs text-ok hover:bg-ok/20"><Radio class="size-3.5" /> Lab hidup: {{ l.name }}</RouterLink>
        </template>
        <template v-if="isLab && live">
          <span class="font-mono text-[10px]" :class="streamState === 'live' ? 'text-ok' : 'text-warn'" data-test="stream-state" :title="streamState === 'live' ? 'Pembaruan didorong server begitu ada event, alert, atau perubahan status' : 'Koneksi real-time terputus; mencoba lagi'">
            ● {{ streamState === 'live' ? 'real-time' : streamState === 'polling' ? 'polling 15 dtk' : 'menyambung…' }}</span>
          <CrButton v-if="live.assessments.length" size="sm" :variant="split ? 'secondary' : 'ghost'" :aria-pressed="split" data-test="toggle-split" @click="toggleSplit"><Columns3 class="size-3.5" /> Red | Blue</CrButton>
          <div class="relative">
            <CrButton size="sm" :variant="sensorOpen ? 'secondary' : 'ghost'" data-test="sensor-button" @click="sensorOpen = !sensorOpen"><Radar class="size-3.5" /> Sensor ({{ activeSensors.length }}<span v-if="failedSensors.length" class="text-sev-critical"> · {{ failedSensors.length }} gagal</span>)</CrButton>
            <div v-if="sensorOpen" class="absolute top-9 right-0 z-30 max-h-[70vh] w-80 overflow-y-auto rounded-md border border-ink-700 bg-ink-900 p-3 text-xs shadow-xl" data-test="sensor-panel">
              <div class="mb-1 font-semibold text-ink-100">Sensor jaringan lab</div>
              <p class="mb-2 text-[11px] text-ink-400">Zeek dan Suricata menangkap lalu lintas jaringan lab secara pasif dan mengirim lognya ke SIEM. Jalur lalu lintas di tampilan ini berasal dari sana.</p>
              <ul v-if="sensors.sensors.length" class="mb-2 space-y-1">
                <li v-for="x in sensors.sensors" :key="x.id" class="flex items-center gap-2 rounded border border-ink-800 px-2 py-1" data-test="sensor-row">
                  <span class="font-mono">{{ x.kind }}</span><span class="text-ink-500">{{ x.subnet_key }}</span>
                  <CrBadge class="ml-auto" :tone="x.status === 'running' ? 'ok' : x.status === 'failed' ? 'critical' : 'neutral'">{{ x.status }}</CrBadge>
                  <span class="font-mono text-[10px] text-ink-500">{{ x.events_total }} ev</span></li>
              </ul>
              <p v-else class="mb-2 text-ink-500">Belum ada sensor terpasang.</p>
              <div v-for="(e, i) in sensorErrors" :key="'e' + i" class="mb-2 rounded border border-sev-critical/40 bg-sev-critical/10 p-1.5 text-[11px]" data-test="sensor-failure">
                <div class="font-medium text-sev-critical">Gagal: {{ e.who.join(', ') }}</div>
                <div class="line-clamp-3 break-all text-ink-300" :title="e.text">{{ e.text }}</div>
                <div v-if="/pull image|failed to resolve/.test(e.text)" class="mt-0.5 text-ink-400">Image sensor belum ada dan tidak bisa diunduh. Pastikan komputer terhubung ke internet (Docker Hub), lalu coba lagi.</div></div>
              <CrButton v-if="canAttachSensors" size="sm" variant="primary" :loading="sensorBusy" data-test="attach-sensors" @click="attachSensors"><Radar class="size-3.5" /> Pasang Zeek + Suricata di semua subnet</CrButton>
              <p v-else class="text-[11px] text-ink-500">Memasang sensor butuh lab berjalan dan izin lab.operate.</p>
              <p v-if="sensorErr" class="mt-1 text-[11px] text-sev-critical" data-test="sensor-error">{{ sensorErr.message }}</p>
            </div>
          </div>
        </template>
        <CrButton size="sm" variant="ghost" @click="scene?.resetView()"><RotateCcw class="size-3.5" /> Reset</CrButton>
        <CrButton size="sm" variant="ghost" @click="scene?.resetView(true)"><ScanEye class="size-3.5" /> Top</CrButton>
        <CrButton size="sm" :variant="labels ? 'secondary' : 'ghost'" :aria-pressed="labels" @click="toggleLabels"><Tags class="size-3.5" /> Labels</CrButton>
        <CrButton v-if="!isLab" size="sm" :variant="flow ? 'secondary' : 'ghost'" :aria-pressed="flow" title="Animasi dekoratif di sepanjang link. Bukan telemetri." @click="toggleFlow"><Waves class="size-3.5" /> Animasi link</CrButton>
        <RouterLink v-if="net" :to="{ name: 'network-editor', params: { id: net.id } }" class="inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-600 bg-ink-800 px-2.5 text-xs text-ink-100 hover:bg-ink-700"><Pencil class="size-3.5" /> Buka di editor</RouterLink>
      </div>
    </div>

    <div class="relative min-h-0 flex-1">
      <div ref="el" class="absolute inset-0 isolate" data-testid="scene3d" />
      <div v-if="!doc" class="absolute inset-0 grid place-items-center"><CrState kind="loading" /></div>
      <div v-else-if="!doc.nodes.length" class="pointer-events-none absolute inset-0 grid place-items-center text-sm text-ink-500">Topologi ini belum memiliki perangkat.</div>
      <div v-if="flow && !isLab" class="absolute bottom-3 left-3 rounded border border-ink-700 bg-ink-900/80 px-2 py-1 font-mono text-[10px] text-ink-400">Animasi link hanya visual, bukan lalu lintas nyata</div>

      <!-- legend -->
      <div :class="['absolute top-3 max-w-[22rem] space-y-1.5 rounded-md border border-ink-700 bg-ink-900/85 p-2 text-[10px] text-ink-300', showSplit ? 'left-1/2 -translate-x-1/2' : 'left-3']" data-test="legend">
        <div v-if="!showSplit" class="flex flex-wrap gap-1.5"><span v-for="(d, t) in DEVICES" :key="t" class="flex items-center gap-1"><span class="size-2 rounded-full" :style="{ background: d.color }" />{{ d.label }}</span></div>
        <template v-if="isLab">
          <div class="flex flex-wrap gap-2 border-t border-ink-800 pt-1.5"><span v-for="s in ['running', 'pending', 'stopped', 'error', 'absent']" :key="s" class="flex items-center gap-1"><span class="size-2 rounded-full" :style="{ background: STATE_COLOR[s] }" />{{ STATE_LABEL[s] }}</span></div>
          <div class="flex flex-wrap gap-2 border-t border-ink-800 pt-1.5">
            <span class="flex items-center gap-1"><span class="h-1 w-4 rounded" :style="{ background: SEV_COLOR[0] }" />koneksi sensor</span>
            <span class="flex items-center gap-1"><span class="h-1 w-4 rounded" :style="{ background: SEV_COLOR[3] }" />koneksi + alert</span>
            <span class="flex items-center gap-1"><span class="h-1 w-4 rounded bg-[#ff3b5c]" />jalur red team</span>
            <span class="flex items-center gap-1"><span class="h-0 w-4 border-t-2 border-dashed border-ink-500" />terisolasi (tak terjangkau)</span>
            <span class="text-ink-500">tebal = jumlah koneksi · partikel = aktivitas terbaru</span>
            <label v-if="allFlowsNow.length > 60" class="flex items-center gap-1 text-ink-400">jalur:
              <select v-model.number="flowLimit" class="rounded border border-ink-700 bg-ink-850 px-1 text-[10px] text-ink-100" data-test="flow-limit" aria-label="Jumlah jalur">
                <option :value="30">30 teramai</option><option :value="60">60 teramai</option><option :value="150">150 teramai</option><option :value="0">semua ({{ allFlowsNow.length }})</option>
              </select></label></div>
          <div v-if="live && !live.access.soc" class="text-warn">Lalu lintas dan alert disembunyikan: butuh izin blueteam.alerts.view.</div>
          <div v-else-if="live && !live.traffic.total_events" class="text-ink-500">Belum ada event Zeek/Suricata untuk IP lab ini di jendela waktu ini.
            <button class="text-accent-300 underline" @click="sensorOpen = true">Pasang sensor</button></div>
        </template>
      </div>

      <!-- red team steps -->
      <div v-if="isLab && assessment && !showSplit" class="absolute bottom-24 left-3 w-80 rounded-md border border-sev-critical/40 bg-ink-900/90 p-2 text-xs" data-test="attack-steps">
        <div class="mb-1 flex items-center gap-2">
          <Crosshair class="size-3.5 text-sev-critical" />
          <select v-model.number="assessmentId" class="min-w-0 flex-1 rounded border border-ink-700 bg-ink-850 px-1 py-0.5 text-[11px] text-ink-100" aria-label="Pilih assessment">
            <option v-for="a in live.assessments" :key="a.id" :value="a.id">#{{ a.id }} {{ a.title }} ({{ a.status }})</option>
          </select>
        </div>
        <div class="mb-1 text-[10px] text-ink-500">Penyerang: <span class="font-mono text-ink-200">{{ label(assessment.attacker_node) }} · {{ assessment.attacker_ip }}</span></div>
        <ol class="space-y-0.5">
          <li v-for="s in steps" :key="s.index" :data-phase="s.phase" :data-step="s.index" :title="s.started_at ? 'Klik untuk memutar ulang dari langkah ini' : ''" @click="s.started_at && jump({ at: s.started_at })" :class="['flex items-center gap-1.5 rounded px-1 py-0.5', s.started_at ? 'cursor-pointer hover:bg-ink-800' : '', s.phase === 'active' ? 'bg-sev-critical/15 text-ink-100' : s.phase === 'done' ? 'text-ink-300' : 'text-ink-500']">
            <span class="w-4 text-right font-mono text-[10px]">{{ s.index + 1 }}</span>
            <span class="min-w-0 flex-1 truncate" :title="s.summary">{{ s.title }}</span>
            <span class="font-mono text-[9px] text-ink-500">{{ s.mitre }}</span>
            <CrBadge :tone="phaseTone[s.phase]">{{ s.phase === 'active' ? 'jalan' : s.phase === 'done' ? 'selesai' : 'menunggu' }}</CrBadge>
          </li>
        </ol>
      </div>

      <!-- timeline / replay -->
      <div v-if="isLab && live" class="absolute bottom-3 z-10 rounded-md border border-ink-700 bg-ink-900/90 px-3 py-2" data-test="timeline"
        :class="showSplit ? [redOpen ? 'left-[21.5rem]' : 'left-14', blueOpen || node || extSel ? 'right-[21.5rem]' : 'right-14'] : ['right-3 left-3', node || extSel ? 'mr-[21rem]' : '']">
        <div class="flex items-center gap-2">
          <CrButton size="sm" :variant="playing ? 'secondary' : 'ghost'" :aria-label="playing ? 'Jeda' : 'Putar ulang'" data-test="play" @click="togglePlay"><component :is="playing ? Pause : Play" class="size-3.5" /> <span class="whitespace-nowrap">{{ playing ? 'Jeda' : 'Putar ulang' }}</span></CrButton>
          <CrButton size="sm" :variant="following ? 'secondary' : 'ghost'" data-test="go-live" @click="goLive"><Activity class="size-3.5" /> Live</CrButton>
          <select v-model.number="minutes" class="rounded border border-ink-700 bg-ink-850 px-1 py-1 text-xs text-ink-100" aria-label="Jendela waktu">
            <option :value="15">15 menit</option><option :value="60">1 jam</option><option :value="240">4 jam</option><option :value="1440">24 jam</option>
          </select>
          <span class="font-mono text-[11px]" :class="following ? 'text-ok' : 'text-accent-300'" data-test="cursor-time">{{ following ? 'LIVE · ' : 'REPLAY · ' }}{{ fmtClock(cursor) }}</span>
          <span v-if="!showSplit" class="ml-auto truncate text-[10px] text-ink-500">semua lapisan mengikuti waktu (status node dari riwayat event lab)</span>
        </div>
        <div class="relative mt-1.5 h-6">
          <div class="absolute inset-x-0 top-2.5 h-1 rounded bg-ink-800" />
          <div class="absolute top-2.5 left-0 h-1 rounded bg-accent-500/50" :style="{ width: cursorPct + '%' }" />
          <button v-for="(m, i) in markers" :key="i" class="absolute top-0.5 z-10 h-5 w-1.5 -translate-x-1/2 rounded-sm opacity-90 hover:opacity-100 hover:ring-2 hover:ring-white/60" :style="{ left: m.x * 100 + '%', background: markerColor(m) }"
            :title="markerTitle(m)" :data-marker="m.kind" :data-count="m.items.length" @click="jump(m)" />
          <input type="range" class="cr3d-range absolute inset-0 w-full" :min="win.start" :max="win.end" :step="1000" :value="cursor" aria-label="Posisi waktu" @input="scrub" />
        </div>
        <div class="flex justify-between font-mono text-[9px] text-ink-500"><span>{{ fmtClock(win.start) }}</span><span>{{ fmtClock(win.end) }}</span></div>
      </div>

      <!-- purple team split: Red (left) | Blue (right) -->
      <button v-if="showSplit && !redOpen" class="absolute top-3 bottom-3 left-3 z-10 flex w-9 flex-col items-center gap-2 rounded-md border border-sev-critical/40 bg-ink-900/95 py-3 text-sev-critical hover:bg-sev-critical/10"
        data-test="red-tab" aria-label="Buka panel Red Team" @click="redOpen = true">
        <Swords class="size-4" /><span class="text-[10px] font-bold tracking-widest [writing-mode:vertical-rl]">RED · {{ score.started }}/{{ assessment.steps.length }}</span></button>
      <aside v-if="showSplit && redOpen" class="absolute top-3 bottom-3 left-3 z-10 flex w-80 flex-col overflow-hidden rounded-md border border-sev-critical/40 bg-ink-900/95" aria-label="Red team" data-test="red-panel">
        <div class="flex items-center gap-2 border-b border-sev-critical/30 bg-sev-critical/10 px-3 py-2">
          <Swords class="size-4 text-sev-critical" /><span class="text-xs font-bold tracking-widest text-sev-critical">RED TEAM</span>
          <span class="ml-auto font-mono text-[10px] text-ink-400">{{ score.started }}/{{ assessment.steps.length }} langkah</span>
          <button class="rounded p-0.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Ciutkan panel Red Team" data-test="red-collapse" @click="redOpen = false"><ChevronsLeft class="size-3.5" /></button></div>
        <div class="space-y-1 border-b border-ink-800 p-2 text-[11px]">
          <select v-model.number="assessmentId" class="w-full rounded border border-ink-700 bg-ink-850 px-1 py-1 text-[11px] text-ink-100" aria-label="Pilih assessment">
            <option v-for="a in live.assessments" :key="a.id" :value="a.id">#{{ a.id }} {{ a.title }} ({{ a.status }})</option></select>
          <div class="text-ink-500">Penyerang: <button class="font-mono text-ink-200 hover:underline" @click="choose(assessment.attacker_node)">{{ label(assessment.attacker_node) }} · {{ assessment.attacker_ip }}</button></div>
          <div v-if="canRun" class="flex items-center gap-1.5 rounded border border-sev-critical/40 bg-sev-critical/10 px-2 py-1.5" data-test="run-box">
            <span class="min-w-0 flex-1 text-[10px] text-rose-200">{{ runArm ? 'Jalankan di lab ini sekarang? Setiap langkah diaudit.' : 'Disetujui, siap dijalankan.' }}</span>
            <CrButton size="sm" :variant="runArm ? 'danger' : 'secondary'" :loading="runBusy" data-test="run-assessment" @click="runAssessment">
              <Play class="size-3.5" /> {{ runArm ? 'Ya, jalankan' : 'Jalankan' }}</CrButton>
            <button v-if="runArm" class="text-[10px] text-ink-400 hover:text-ink-100" data-test="run-cancel" @click="runArm = false">batal</button></div>
          <p v-if="runErr" class="text-[10px] text-sev-critical">{{ runErr.message }}</p>
          <div v-if="assessment.isolated_targets.length" class="rounded border border-ink-700 bg-ink-850 px-2 py-1 text-[10px] text-ink-400" data-test="isolation-note">
            Target di subnet lain ({{ assessment.isolated_targets.map(label).join(', ') }}) tidak terjangkau: setiap subnet lab Docker diisolasi, juga lewat router/firewall lab. Hasil "closed" pada target itu bukan bukti aman.</div>
        </div>
        <ol class="min-h-0 flex-1 space-y-1.5 overflow-y-auto p-2">
          <li v-for="s in steps" :key="s.index" :data-step="s.index" :data-phase="s.phase" @mouseenter="hoverStep = s.index" @mouseleave="hoverStep = null"
            @click="s.started_at && jump({ at: s.started_at })"
            :class="['rounded border px-2 py-1.5 text-[11px] transition', s.started_at ? 'cursor-pointer' : '', hoverStep === s.index ? 'border-sev-critical ring-1 ring-sev-critical/60' : s.phase === 'active' ? 'border-sev-critical/70 bg-sev-critical/10' : 'border-ink-800']">
            <div class="flex items-center gap-1.5"><span class="font-mono text-[10px] text-ink-500">{{ s.index + 1 }}</span>
              <span class="min-w-0 flex-1 truncate font-medium text-ink-100">{{ s.title }}</span>
              <CrBadge :tone="phaseTone[s.phase]">{{ s.phase === 'active' ? 'jalan' : s.phase === 'done' ? 'selesai' : 'menunggu' }}</CrBadge></div>
            <div class="font-mono text-[9px] text-ink-500">{{ s.mitre }} · {{ s.tactic }}</div>
            <div v-if="s.targets.length" class="mt-1 flex flex-wrap gap-1">
              <span v-for="k in s.targets" :key="k" :class="['rounded px-1 text-[10px]', s.isolated_targets.includes(k) ? 'bg-ink-800 text-ink-500 line-through decoration-ink-500' : 'bg-sev-critical/15 text-rose-200']"
                :title="s.isolated_targets.includes(k) ? 'Subnet lain: tidak terjangkau dari penyerang' : ''">{{ label(k) }}</span></div>
            <div v-if="s.phase === 'done' && s.summary" class="mt-1 text-[10px] text-ink-400">{{ s.summary.replace(/^Step \d+ done: /, '') }}</div>
          </li>
        </ol>
      </aside>

      <button v-if="showSplit && !blueOpen" class="absolute top-3 right-3 bottom-3 z-10 flex w-9 flex-col items-center gap-2 rounded-md border border-sky-500/40 bg-ink-900/95 py-3 text-sky-400 hover:bg-sky-500/10"
        data-test="blue-tab" aria-label="Buka panel Blue Team" @click="blueOpen = true">
        <Shield class="size-4" /><span class="text-[10px] font-bold tracking-widest [writing-mode:vertical-rl]">BLUE · {{ score.detected }}/{{ score.started }}</span>
        <span v-if="score.missed" class="rounded bg-sev-critical/20 px-1 text-[9px] text-sev-critical">{{ score.missed }} lolos</span></button>
      <aside v-if="showSplit && blueOpen" class="absolute top-3 right-3 bottom-3 z-10 flex w-80 flex-col overflow-hidden rounded-md border border-sky-500/40 bg-ink-900/95" aria-label="Blue team" data-test="blue-panel">
        <div class="flex items-center gap-2 border-b border-sky-500/30 bg-sky-500/10 px-3 py-2">
          <Shield class="size-4 text-sky-400" /><span class="text-xs font-bold tracking-widest text-sky-400">BLUE TEAM</span>
          <span class="ml-auto font-mono text-[10px] text-ink-400" data-test="purple-score">{{ score.detected }}/{{ score.started }} terdeteksi</span>
          <button class="rounded p-0.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Ciutkan panel Blue Team" data-test="blue-collapse" @click="blueOpen = false"><ChevronsRight class="size-3.5" /></button></div>
        <div v-if="score.detected && score.sensor < score.detected" class="border-b border-warn/30 bg-warn/10 px-3 py-1.5 text-[10px] text-warn" data-test="evidence-warning">
          <b>{{ score.sensor }}/{{ score.detected }}</b> deteksi didukung sensor jaringan. Sisanya hanya dari catatan aplikasi tentang aksi red team:
          rule-nya terbukti bekerja, tapi belum terbukti jaringan melihat serangannya.
          <button v-if="!activeSensors.length" class="underline" @click="sensorOpen = true">Pasang sensor</button></div>
        <div class="grid grid-cols-4 gap-1 border-b border-ink-800 p-2 text-center text-[10px]">
          <div class="rounded bg-ok/10 py-1"><div class="font-mono text-sm text-ok">{{ score.same }}</div>teknik sama</div>
          <div class="rounded bg-sky-500/10 py-1" title="Deteksi yang buktinya berasal dari sensor jaringan (Zeek/Suricata)"><div class="font-mono text-sm text-sky-300" data-test="sensor-score">{{ score.sensor }}</div>oleh sensor</div>
          <div class="rounded bg-sev-critical/10 py-1"><div class="font-mono text-sm text-sev-critical">{{ score.missed }}</div>lolos</div>
          <div class="rounded bg-ink-800 py-1"><div class="font-mono text-sm text-ink-100">{{ fmtTtd(score.meanTtd) }}</div>rata-rata deteksi</div>
        </div>
        <div class="min-h-0 flex-1 overflow-y-auto">
          <ol class="space-y-1.5 p-2">
            <li v-for="r in blueRows" :key="r.step.index" :data-verdict="r.det.verdict" :data-step="r.step.index" @mouseenter="hoverStep = r.step.index" @mouseleave="hoverStep = null"
              :class="['rounded border px-2 py-1.5 text-[11px] transition', hoverStep === r.step.index ? 'border-sky-400 ring-1 ring-sky-400/60' : r.det.verdict === 'missed' ? 'border-sev-critical/50' : 'border-ink-800']">
              <div class="flex items-center gap-1.5"><span class="font-mono text-[10px] text-ink-500">{{ r.step.index + 1 }}</span>
                <span class="min-w-0 flex-1 truncate text-ink-300">{{ r.step.title }}</span>
                <CrBadge :tone="VERDICT_TONE[r.det.verdict]">{{ VERDICT_LABEL[r.det.verdict] }}</CrBadge>
                <span v-if="r.det.alerts.length" :class="['rounded px-1 font-mono text-[9px]', r.det.evidence.includes('sensor') ? 'bg-sky-500/20 text-sky-300' : 'bg-warn/15 text-warn']"
                  :title="r.det.evidence.includes('sensor') ? 'Dilihat sensor jaringan' : 'Hanya catatan aplikasi'">{{ r.det.evidence.includes('sensor') ? 'SENSOR' : 'APP' }}</span></div>
              <template v-if="r.det.alerts.length">
                <div class="mt-0.5 text-[10px] text-ink-400">dalam <span class="font-mono text-ink-100">{{ fmtTtd(r.det.ttd) }}</span> ·
                  {{ [...new Set(r.det.alerts.map((a) => a.rule))].join(', ') }}</div>
                <div class="text-[10px]" :class="r.det.evidence.includes('sensor') ? 'text-ok' : 'text-warn'">
                  bukti: {{ r.det.evidence.includes('sensor') ? 'sensor jaringan' : 'catatan aplikasi saja (belum dilihat sensor)' }}</div>
              </template>
              <div v-else-if="r.det.verdict === 'missed'" class="mt-0.5 text-[10px] text-sev-critical">Tidak ada alert untuk teknik {{ r.step.mitre }}. Celah deteksi.</div>
            </li>
          </ol>
          <div class="border-t border-ink-800 p-2">
            <div class="panel-title mb-1">Alert masuk</div>
            <p v-if="!alertFeed.length" class="text-[11px] text-ink-500">Belum ada alert sampai waktu ini.</p>
            <button v-for="a in alertFeed" :key="a.id" class="mb-1 flex w-full items-center gap-1.5 rounded px-1 py-0.5 text-left text-[11px] hover:bg-ink-800" data-test="alert-feed"
              @click="a.nodes[0] && choose(a.nodes[0].key)">
              <SevBadge :sev="a.severity" /><span class="min-w-0 flex-1 truncate text-ink-200" :title="a.title">{{ a.title }}</span>
              <span class="font-mono text-[9px] text-ink-500">{{ fmtClock(Date.parse(a.first_seen)) }}</span></button>
          </div>
        </div>
      </aside>

      <!-- node panel -->
      <aside v-if="node || extSel" class="panel absolute top-3 right-3 bottom-3 z-20 flex w-80 flex-col overflow-hidden !bg-ink-900" aria-label="Detail perangkat" data-test="node-panel">
        <div class="panel-header">
          <div class="flex min-w-0 items-center gap-2">
            <component :is="DEVICES[node?.type || 'internet'].icon" class="size-4 shrink-0" :style="{ color: DEVICES[node?.type || 'internet'].color }" />
            <span class="truncate text-sm font-semibold text-ink-100">{{ node?.label || extSel }}</span>
            <span v-if="lnode" class="rounded px-1.5 py-0.5 text-[10px] font-medium" data-test="node-state" :style="{ color: STATE_COLOR[lnode.state], background: STATE_COLOR[lnode.state] + '22' }">{{ STATE_LABEL[lnode.state] }}</span>
          </div>
          <button class="text-ink-400 hover:text-ink-100" aria-label="Tutup" @click="choose(null)"><X class="size-4" /></button>
        </div>
        <div class="flex flex-wrap gap-1.5 border-b border-ink-800 px-3 py-2">
          <CrButton size="sm" variant="ghost" data-test="focus" @click="focusNode()"><Crosshair class="size-3.5" /> Fokus</CrButton>
          <CrButton v-if="isLab && node" size="sm" variant="ghost" :disabled="!canTerminal" :title="canTerminal ? 'Buka terminal di container ini' : 'Terminal butuh lab dan container berjalan serta izin lab.terminal'" data-test="open-terminal" @click="termNode = { key: node.key, label: node.label }"><SquareTerminal class="size-3.5" /> Terminal</CrButton>
          <CrButton v-if="isLab && nodeIps.length && live?.access.soc" size="sm" variant="ghost" @click="openSiem"><Activity class="size-3.5" /> Buka di SIEM</CrButton>
        </div>
        <div v-if="isLab" class="flex border-b border-ink-800 text-xs" role="tablist">
          <button v-for="t in [['info', 'Info'], ['flows', `Koneksi (${nodeFlows.length})`], ['events', 'Event SIEM'], ['alerts', `Alert (${nodeAlerts.length})`]]" :key="t[0]" role="tab" :aria-selected="tab === t[0]" :data-tab="t[0]"
            :class="['flex-1 px-1 py-2', tab === t[0] ? 'border-b-2 border-accent-400 text-ink-100' : 'text-ink-400 hover:text-ink-200']" @click="tab = t[0]">{{ t[1] }}</button>
        </div>
        <div class="min-h-0 flex-1 space-y-4 overflow-y-auto p-4 text-sm">
          <template v-if="tab === 'info' || !isLab">
            <dl v-if="node" class="grid grid-cols-[90px_1fr] gap-y-1 text-xs">
              <dt class="text-ink-500">Tipe</dt><dd>{{ DEVICES[node.type].label }}</dd>
              <dt class="text-ink-500">Hostname</dt><dd class="font-mono">{{ node.hostname || '—' }}</dd>
              <dt class="text-ink-500">OS</dt><dd>{{ node.os || '—' }}</dd>
              <dt class="text-ink-500">Zona</dt><dd>{{ zoneName(node.zone) }}</dd>
              <template v-if="lnode">
                <dt class="text-ink-500">Berjalan di</dt><dd class="font-mono">{{ lnode.backing === 'none' ? (lnode.skipped ? 'tidak di-deploy (desain)' : '—') : `${lnode.backing} ${lnode.name || ''}` }}</dd>
                <dt class="text-ink-500">Status mentah</dt><dd class="font-mono">{{ lnode.raw_status || '—' }}</dd>
                <template v-if="lnode.stats"><dt class="text-ink-500">CPU / RAM</dt><dd class="font-mono">{{ lnode.stats.cpu_pct }}% · {{ fmtBytes(lnode.stats.mem_bytes) }}</dd></template>
              </template>
            </dl>
            <dl v-else class="grid grid-cols-[90px_1fr] gap-y-1 text-xs"><dt class="text-ink-500">Alamat</dt><dd class="font-mono">{{ extSel }}</dd><dt class="text-ink-500">Asal</dt><dd>di luar topologi lab (terlihat di lalu lintas sensor)</dd></dl>
            <div v-if="node"><div class="panel-title mb-1">Interfaces {{ lnode?.ips_planned ? '(IP rencana)' : '' }}</div>
              <template v-if="lnode && Object.keys(lnode.ips).length"><div v-for="(ip, sk) in lnode.ips" :key="sk" class="font-mono text-xs" data-test="node-ip">{{ ip }} <span class="text-ink-500">{{ subnet(sk)?.cidr || sk }}</span></div></template>
              <template v-else><div v-for="i in node.interfaces" :key="i.name" class="font-mono text-xs">{{ i.name }} · {{ i.ip || 'no ip' }} <span class="text-ink-500">{{ subnet(i.subnet)?.cidr || '' }}</span></div>
                <p v-if="!node.interfaces.length" class="text-xs text-ink-500">Tidak ada</p></template></div>
            <div v-if="node?.properties?.services?.length"><div class="panel-title mb-1">Port / layanan</div>
              <div class="flex flex-wrap gap-1"><CrBadge v-for="s in node.properties.services" :key="s.port + s.proto" tone="accent">{{ s.port }}/{{ s.proto }} {{ s.name }}</CrBadge></div></div>
            <div v-if="node"><div class="panel-title mb-1">Link topologi ({{ neighbors.length }})</div>
              <button v-for="n in neighbors" :key="n.link.key" class="flex w-full items-center justify-between rounded px-1.5 py-1 text-left text-xs hover:bg-ink-800" @click="choose(n.node.key)">
                <span class="text-ink-200">{{ n.node.label }}</span><span class="font-mono text-[10px] text-ink-500">{{ n.link.kind }}{{ n.link.bandwidth_mbps ? ` · ${n.link.bandwidth_mbps}M` : '' }}</span></button></div>
            <div v-if="nodeIssues.length"><div class="panel-title mb-1">Validasi</div>
              <p v-for="(i, x) in nodeIssues" :key="x" :class="['text-xs', i.severity === 'error' ? 'text-sev-critical' : 'text-warn']">{{ $tr(i.message) }}</p></div>
          </template>

          <template v-else-if="tab === 'flows'">
            <p v-if="!nodeFlows.length" class="text-xs text-ink-500">Tidak ada koneksi sensor untuk node ini sampai waktu yang dipilih.</p>
            <button v-for="f in nodeFlows" :key="f.src_ip + f.dst_ip" class="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-xs hover:bg-ink-800" data-test="flow-row" @click="choose(f.src === selectedKey ? f.dst : f.src)">
              <span class="min-w-0 flex-1 truncate"><span class="text-ink-200">{{ label(f.src) }}</span> → <span class="text-ink-200">{{ label(f.dst) }}</span>
                <span class="block font-mono text-[10px] text-ink-500">{{ f.protocols.join(', ') || '—' }} · {{ f.datasets.join(', ') }}</span></span>
              <span class="font-mono text-[11px]" :style="{ color: SEV_COLOR[f.max_severity] }">{{ f.total }}</span></button>
          </template>

          <template v-else-if="tab === 'events'">
            <CrState v-if="events.loading" kind="loading" />
            <p v-else-if="events.error" class="text-xs text-sev-critical">{{ events.error.message }}</p>
            <p v-else-if="!events.items.length" class="text-xs text-ink-500">Tidak ada event SIEM untuk {{ nodeIps.join(', ') || 'node ini' }} di jendela waktu ini.</p>
            <ul v-else class="space-y-1.5" data-test="node-events">
              <li v-for="e in events.items" :key="e.id" class="rounded border border-ink-800 px-2 py-1 text-[11px]">
                <div class="flex items-center gap-1.5"><SevBadge :sev="e.severity" /><span class="font-mono text-ink-400">{{ e.dataset }}</span><span class="ml-auto text-[10px] text-ink-500">{{ ago(e.occurred_at) }}</span></div>
                <div class="mt-0.5 font-mono text-[10px] text-ink-300">{{ e.src_ip || '—' }}{{ e.src_port ? ':' + e.src_port : '' }} → {{ e.dst_ip || '—' }}{{ e.dst_port ? ':' + e.dst_port : '' }}</div>
                <div class="truncate text-ink-200" :title="e.message">{{ e.signature || e.message }}</div></li>
            </ul>
          </template>

          <template v-else-if="tab === 'alerts'">
            <p v-if="!nodeAlerts.length" class="text-xs text-ink-500">Tidak ada alert yang melibatkan node ini di jendela waktu ini.</p>
            <ul v-else class="space-y-1.5" data-test="node-alerts">
              <li v-for="a in nodeAlerts" :key="a.id" class="rounded border border-ink-800 px-2 py-1.5 text-[11px]">
                <div class="flex items-center gap-1.5"><SevBadge :sev="a.severity" /><span class="text-[10px] text-ink-400">{{ a.status }}</span>
                  <span class="ml-auto text-[10px] text-ink-500">{{ a.roles.includes('source') ? 'sumber' : '' }}{{ a.roles.length > 1 ? ' + ' : '' }}{{ a.roles.includes('target') ? 'target' : '' }}</span></div>
                <div class="mt-0.5 text-ink-100">{{ a.title }}</div>
                <div class="flex items-center justify-between text-[10px] text-ink-500"><span>{{ a.event_count }} event · {{ ago(a.last_seen) }}</span>
                  <RouterLink :to="{ name: 'defense-center' }" class="text-accent-300 hover:underline">Defense Center</RouterLink></div></li>
            </ul>
          </template>
        </div>
      </aside>
    </div>

    <section v-if="termNode && isLab" class="fixed inset-x-0 bottom-0 z-40 flex h-[45vh] flex-col border-t border-accent-400/40 bg-ink-900 shadow-2xl lg:left-[var(--sidebar-w,16rem)]" aria-label="Terminal lab" data-test="terminal-drawer">
      <div class="flex items-center gap-2 border-b border-ink-800 px-3 py-1.5 text-xs text-ink-300"><SquareTerminal class="size-3.5" /> Terminal · {{ termNode.label }}
        <button class="ml-auto rounded p-1 hover:bg-ink-800 hover:text-ink-100" aria-label="Tutup panel terminal" @click="termNode = null"><X class="size-4" /></button></div>
      <LabTerminal class="min-h-0 flex-1" :lab-id="live.lab.id" :node-key="termNode.key" :label="termNode.label" :key="termNode.key" />
    </section>
  </div>
</template>

<style>
.cr3d-label { font: 500 11px "Inter Variable", sans-serif; color: #e8eef7; text-align: center; text-shadow: 0 1px 3px #000; white-space: nowrap; line-height: 1.25; }
.cr3d-label .ip { font: 10px "JetBrains Mono Variable", monospace; color: #67e8f9; }
.cr3d-label .st { font-size: 10px; }
.cr3d-label .alert { font-size: 10px; color: #fb7185; font-weight: 600; }
.cr3d-label .attacker { font-size: 10px; color: #ff3b5c; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; }
.cr3d-label .planned, .cr3d-label .ext { font-size: 9px; color: #94a3b8; }
.cr3d-zone { font-size: 12px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; }
.cr3d-range { -webkit-appearance: none; appearance: none; background: transparent; cursor: pointer; }
.cr3d-range::-webkit-slider-thumb { -webkit-appearance: none; width: 12px; height: 22px; border-radius: 3px; background: #22d3ee; box-shadow: 0 0 0 2px #050a14; }
.cr3d-range::-moz-range-thumb { width: 12px; height: 22px; border-radius: 3px; background: #22d3ee; border: 0; }
</style>
