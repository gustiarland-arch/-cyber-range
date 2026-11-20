<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Pause, Play, Radio } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, asDate, fmtTime } from '@/services/format'
import { ALERT_STATUS_TONE, SEV_COLOR, useSocStream } from '@/services/soc'
import EChart from '@/components/charts/EChart.vue'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import EventModal from '@/components/soc/EventModal.vue'
import EventTable from '@/components/soc/EventTable.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const router = useRouter()
const events = ref([])
const alerts = ref([])
const paused = ref(false)
const buffered = ref(0)
const loaded = ref(false)
const err = ref(null)
const selected = ref(null)
const tick = ref(Date.now())
let clock = null
const WINDOW_MIN = 15

async function load() {
  try {
    const to = new Date(); const from = new Date(to - WINDOW_MIN * 60e3)
    const [ev, al] = await Promise.all([
      api('/soc/events', { query: { from: from.toISOString(), to: to.toISOString(), page_size: 200, stats: false } }),
      api('/soc/alerts', { query: { status: 'open', page_size: 12 } }),
    ])
    events.value = ev.items; alerts.value = al.items; loaded.value = true
  } catch (e) { err.value = e }
}
const pending = []
const { state } = useSocStream((m) => {
  if (m.type === 'events') {
    const items = m.data.latest.map((e) => ({ ...e, id: e.id }))
    if (paused.value) { pending.push(...items); buffered.value = pending.length; return }
    events.value = [...items.reverse(), ...events.value].slice(0, 500)
  } else if (m.type === 'alert') {
    const i = alerts.value.findIndex((a) => a.id === m.data.id)
    if (['resolved', 'false_positive'].includes(m.data.status)) { if (i >= 0) alerts.value.splice(i, 1); return }
    if (i >= 0) alerts.value[i] = { ...alerts.value[i], ...m.data, last_seen: m.data.last_seen || alerts.value[i].last_seen }
    else alerts.value = [{ ...m.data, last_seen: m.data.last_seen || new Date().toISOString() }, ...alerts.value].slice(0, 12)
  }
})
function resume() { paused.value = false; events.value = [...pending.reverse(), ...events.value].slice(0, 500); pending.length = 0; buffered.value = 0 }
onMounted(() => { load(); clock = setInterval(() => { tick.value = Date.now() }, 5000) })
onBeforeUnmount(() => clearInterval(clock))

const rate = computed(() => {
  const now = tick.value
  const bins = Array.from({ length: WINDOW_MIN }, () => [0, 0, 0, 0, 0])
  for (const e of events.value) {
    const age = Math.floor((now - asDate(e.occurred_at)) / 60e3)
    if (age >= 0 && age < WINDOW_MIN) bins[WINDOW_MIN - 1 - age][e.severity] += 1
  }
  return bins
})
const rateOption = computed(() => ({
  grid: { left: 32, right: 8, top: 10, bottom: 22 }, tooltip: { trigger: 'axis' },
  xAxis: { type: 'category', data: rate.value.map((_, i) => `-${WINDOW_MIN - 1 - i}m`), axisLabel: { color: '#6b84a6', fontSize: 10 }, axisLine: { lineStyle: { color: '#22395a' } } },
  yAxis: { type: 'value', minInterval: 1, axisLabel: { color: '#6b84a6', fontSize: 10 }, splitLine: { lineStyle: { color: '#16263d' } } },
  series: ['info', 'low', 'medium', 'high', 'critical'].map((n, s) => ({ name: n, type: 'bar', stack: 'sev', itemStyle: { color: SEV_COLOR[s] }, data: rate.value.map((b) => b[s]) })),
}))
const lastMinute = computed(() => rate.value[WINDOW_MIN - 1].reduce((a, b) => a + b, 0))
const stateTone = { live: 'ok', connecting: 'warn', offline: 'bad', denied: 'bad' }
</script>

<template>
  <PageHeader section="Command Center" title="Monitor Keamanan Real-time" subtitle="Aliran event dan alert langsung dari setiap sumber log, dikirim melalui WebSocket.">
    <CrBadge :tone="stateTone[state]" data-test="stream-state"><Radio class="size-3" /> {{ state }}</CrBadge>
    <CrButton v-if="!paused" @click="paused = true"><Pause class="size-4" /> Jeda</CrButton>
    <CrButton v-else variant="primary" @click="resume"><Play class="size-4" /> Resume ({{ buffered }} new)</CrButton>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!loaded" kind="loading" />
  <div v-else class="grid gap-4 xl:grid-cols-3">
    <div class="space-y-4 xl:col-span-2">
      <CrPanel :title="`Event per menit · ${lastMinute} dalam satu menit terakhir`"><EChart :option="rateOption" height="170px" /></CrPanel>
      <CrPanel title="Event langsung" :subtitle="`${events.length} ditampilkan · terbaru dulu`" :padded="false">
        <CrState v-if="!events.length" kind="empty" message="Menunggu event. Sensor mengirim ke ingest API; telemetri audit platform diteruskan setiap 10 detik." />
        <div v-else class="max-h-[34rem] overflow-y-auto" data-test="live-events"><EventTable :items="events.slice(0, 200)" compact @select="selected = $event.id" /></div>
      </CrPanel>
    </div>
    <CrPanel title="Alert terbuka" :padded="false">
      <CrState v-if="!alerts.length" kind="empty" message="Tidak ada alert terbuka." />
      <ul v-else class="divide-y divide-ink-800" data-test="live-alerts">
        <li v-for="a in alerts" :key="a.id" class="cursor-pointer px-4 py-2.5 hover:bg-ink-800/60" @click="router.push({ name: 'incident-response', query: { alert: a.id } })">
          <div class="flex items-center gap-2"><SevBadge :sev="a.severity" /><CrBadge :tone="ALERT_STATUS_TONE[a.status]">{{ $st(a.status) }}</CrBadge><DemoTag v-if="a.is_demo" /><span class="ml-auto font-mono text-[10px] text-ink-500" :title="fmtTime(a.last_seen)">{{ ago(a.last_seen) }}</span></div>
          <div class="mt-1 text-sm text-ink-100">{{ a.title }}</div><div class="font-mono text-[11px] text-ink-500">#{{ a.id }} · {{ a.event_count }} event</div>
        </li>
      </ul>
    </CrPanel>
  </div>
  <EventModal :event-id="selected" @close="selected = null" @pivot="(t) => router.push({ name: 'siem', query: { q: t } })" />
</template>
