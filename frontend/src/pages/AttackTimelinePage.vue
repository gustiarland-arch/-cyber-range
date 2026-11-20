<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Pause, Play, RotateCcw, SkipForward } from 'lucide-vue-next'
import { api } from '@/services/api'
import { asDate, fmtTime } from '@/services/format'
import { STATUS_TONE, statusLabel } from '@/components/redteam/rt'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const route = useRoute()
const router = useRouter()
const list = ref(null)
const a = ref(null)
const err = ref(null)
async function loadList() {
  try { list.value = (await api('/redteam/assessments', { query: { status: 'all' } })).filter((x) => ['completed', 'aborted', 'failed'].includes(x.status)) } catch (e) { err.value = e }
}
async function loadOne(id) {
  a.value = null; stop(); cursor.value = 0
  if (!id) return
  try { a.value = await api(`/redteam/assessments/${id}`); err.value = null } catch (e) { err.value = e }
}
onMounted(() => { loadList(); loadOne(route.query.id) })
watch(() => route.query.id, loadOne)

// Replay is driven by real recorded timestamps: events and findings are revealed in the order and spacing they happened.
const items = computed(() => {
  if (!a.value) return []
  const ev = a.value.timeline.map((e) => ({ t: asDate(e.at).getTime(), type: 'event', e }))
  const fi = a.value.findings.map((f) => ({ t: asDate(f.at).getTime(), type: 'finding', f }))
  return [...ev, ...fi].sort((x, y) => x.t - y.t || (x.type === 'event' ? -1 : 1))
})
const cursor = ref(0) // number of items revealed
const shown = computed(() => items.value.slice(0, cursor.value))
const nowT = computed(() => shown.value.at(-1)?.t)
const t0 = computed(() => items.value[0]?.t)
let timer = null
const playing = ref(false)
function stop() { playing.value = false; clearTimeout(timer) }
function tick() {
  if (cursor.value >= items.value.length) return stop()
  cursor.value += 1
  const next = items.value[cursor.value]
  if (!next) return stop()
  const gap = Math.min(1500, Math.max(150, (next.t - items.value[cursor.value - 1].t) / 4)) // 4x speed, clamped
  timer = setTimeout(tick, gap)
}
function play() { if (cursor.value >= items.value.length) cursor.value = 0; playing.value = true; tick() }
onBeforeUnmount(stop)

// ---- map: attacker on the left, targets on the right
const W = 640
const H = computed(() => Math.max(180, (a.value?.targets.length || 1) * 70 + 40))
const targets = computed(() => (a.value?.targets || []).map((t, i, arr) => ({ ...t, x: 480, y: (H.value / (arr.length + 1)) * (i + 1) })))
const ipTo = computed(() => Object.fromEntries(targets.value.flatMap((t) => t.ips.map((ip) => [ip, t.node_key]))))
const state = computed(() => {
  const s = Object.fromEntries(targets.value.map((t) => [t.node_key, { up: false, ports: new Set(), sev: -1 }]))
  for (const it of shown.value) {
    if (it.type !== 'finding') continue
    const k = ipTo.value[it.f.target_ip]; if (!k) continue
    if (it.f.kind === 'host_up') s[k].up = true
    if (it.f.port) { s[k].ports.add(it.f.port); s[k].up = true }
    s[k].sev = Math.max(s[k].sev, it.f.severity)
  }
  return s
})
const activeStep = computed(() => {
  let step = null
  for (const it of shown.value) if (it.type === 'event') { if (it.e.kind === 'step_started') step = it.e.step; if (it.e.kind === 'step_finished') step = null }
  return step
})
const sevColor = (s) => ['#60a5fa', '#a3e635', '#facc15', '#fb923c', '#f43f5e'][Math.min(4, Math.max(0, s))]
const offset = (t) => `+${((t - t0.value) / 1000).toFixed(1)}s`
</script>

<template>
  <PageHeader section="Red Team Operations" title="Timeline Serangan" subtitle="Putar ulang aktivitas assessment yang terekam langkah demi langkah">
    <select class="input !w-80" :value="route.query.id || ''" aria-label="Assessment" @change="router.replace({ query: { id: $event.target.value || undefined } })">
      <option value="">Pilih assessment yang sudah selesai…</option>
      <option v-for="x in list || []" :key="x.id" :value="String(x.id)">#{{ x.id }} {{ x.title }} ({{ $st(x.status) }})</option>
    </select>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="loadOne(route.query.id)" />
  <CrState v-else-if="!route.query.id" kind="empty" :message="list && !list.length ? 'Belum ada assessment yang selesai. Jalankan dari Attack Simulation.' : 'Pilih assessment untuk diputar ulang.'" />
  <CrState v-else-if="!a" kind="loading" />
  <template v-else>
    <CrPanel class="mb-4">
      <div class="flex flex-wrap items-center gap-3">
        <CrButton v-if="!playing" variant="primary" data-test="play" @click="play"><Play class="size-4" /> {{ cursor >= items.length && cursor ? 'Replay' : 'Play' }}</CrButton>
        <CrButton v-else @click="stop"><Pause class="size-4" /> Jeda</CrButton>
        <CrButton variant="ghost" title="Reset" @click="stop(); cursor = 0"><RotateCcw class="size-4" /></CrButton>
        <CrButton variant="ghost" title="Tampilkan semua" @click="stop(); cursor = items.length"><SkipForward class="size-4" /></CrButton>
        <input v-model.number="cursor" type="range" min="0" :max="items.length" class="flex-1 accent-[var(--color-accent-500)]" aria-label="Posisi replay" @input="stop" />
        <span class="font-mono text-xs text-ink-400" data-test="cursor">{{ cursor }}/{{ items.length }} {{ nowT ? offset(nowT) : '' }}</span>
        <CrBadge :tone="STATUS_TONE[a.status]">{{ statusLabel(a.status) }}</CrBadge>
        <RouterLink :to="{ name: 'assessment', params: { id: a.id } }" class="text-xs text-accent-300 hover:underline">Buka assessment</RouterLink>
      </div>
    </CrPanel>
    <div class="grid gap-4 xl:grid-cols-3">
      <CrPanel class="xl:col-span-2" :title="`${a.scenario.code} · ${a.title}`" :subtitle="activeStep !== null ? `Running step ${activeStep + 1}: ${a.steps[activeStep]?.title}` : `Lab ${a.lab}`">
        <svg :viewBox="`0 0 ${W} ${H}`" class="w-full" role="img" aria-label="Replay jalur serangan">
          <g v-for="t in targets" :key="t.node_key">
            <line x1="150" :y1="H / 2" :x2="t.x - 60" :y2="t.y" :stroke="state[t.node_key].up ? sevColor(state[t.node_key].sev) : '#334155'" :stroke-width="state[t.node_key].up ? 2.5 : 1" :stroke-dasharray="state[t.node_key].up ? '' : '4 4'" />
            <rect :x="t.x - 60" :y="t.y - 22" width="150" height="44" rx="8" fill="#0f172a" :stroke="state[t.node_key].up ? sevColor(state[t.node_key].sev) : '#334155'" :data-node="t.node_key" :data-up="state[t.node_key].up" />
            <text :x="t.x - 50" :y="t.y - 5" fill="#e2e8f0" font-size="12">{{ t.label }}</text>
            <text :x="t.x - 50" :y="t.y + 12" fill="#94a3b8" font-size="10" font-family="monospace">{{ t.ips[0] }}{{ state[t.node_key].ports.size ? ` · ${[...state[t.node_key].ports].join(',')}` : '' }}</text>
          </g>
          <rect x="20" :y="H / 2 - 24" width="130" height="48" rx="8" fill="#1f0a10" stroke="#f43f5e" />
          <text x="30" :y="H / 2 - 5" fill="#fecdd3" font-size="12">{{ a.attacker_node }}</text>
          <text x="30" :y="H / 2 + 12" fill="#fda4af" font-size="10" font-family="monospace">{{ a.attacker_ip }}</text>
        </svg>
      </CrPanel>
      <CrPanel title="Log replay" :padded="false">
        <ol class="max-h-[28rem] divide-y divide-ink-800 overflow-y-auto" data-test="replay-log">
          <li v-for="(it, i) in shown" :key="i" class="px-4 py-2 text-xs">
            <div class="flex justify-between font-mono text-[10px] text-ink-500"><span>{{ offset(it.t) }}</span><span>{{ fmtTime(it.e?.at || it.f?.at) }}</span></div>
            <div v-if="it.type === 'event'" class="text-ink-300"><CrBadge>{{ $st(it.e.kind) }}</CrBadge> {{ $tr(it.e.message) }}</div>
            <div v-else class="flex items-center gap-2 text-ink-100"><SevBadge :sev="it.f.severity" /> {{ it.f.title }}</div>
          </li>
          <li v-if="!shown.length" class="px-4 py-6 text-center text-xs text-ink-500">Press Play to replay {{ items.length }} event dan temuan yang terekam.</li>
        </ol>
      </CrPanel>
    </div>
  </template>
</template>
