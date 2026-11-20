<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Database, FlaskConical, Play, Plus, RefreshCw, RotateCw, Search, Trash2, Upload } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { saveTextFile } from '@/services/soc'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import EChart from '@/components/charts/EChart.vue'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPagination from '@/components/ui/CrPagination.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import EventModal from '@/components/soc/EventModal.vue'
import EventTable from '@/components/soc/EventTable.vue'

const props = defineProps({ mode: { type: String, default: 'siem' } }) // siem | ids
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const isIds = computed(() => props.mode === 'ids')
const RANGES = { '15m': 0.25, '1h': 1, '24h': 24, '7d': 168, '30d': 720 }
const tab = ref(route.query.tab === 'sources' ? 'sources' : 'search')

const form = reactive({ q: route.query.q || (isIds.value ? 'cat:ids' : ''), range: route.query.range || '24h', demo: route.query.demo !== '0' })
const page = ref(1)
const res = ref(null)
const err = ref(null)
const loading = ref(false)
const selected = ref(null)

async function search() {
  loading.value = true; err.value = null
  const to = new Date()
  const from = new Date(to.getTime() - RANGES[form.range] * 3600e3)
  try {
    res.value = await api('/soc/events', { query: { q: form.q, from: from.toISOString(), to: to.toISOString(), include_demo: form.demo, page: page.value, page_size: 50 } })
    router.replace({ query: { ...route.query, q: form.q || undefined, range: form.range, demo: form.demo ? undefined : '0' } })
  } catch (e) { err.value = e } finally { loading.value = false }
}
function run() { page.value = 1; search() }
watch(page, search)
onMounted(() => { search(); if (tab.value === 'sources') loadSources() })

function addTerm(t) { form.q = form.q.split(/\s+/).includes(t) ? form.q : `${form.q} ${t}`.trim(); run() }
function pivot(t) { selected.value = null; addTerm(t) }
const FACET_KEY = { src_ip: 'src', dst_ip: 'dst', category: 'cat', dataset: 'dataset', signature: 'sig' }
const facetTerm = (f, v) => `${FACET_KEY[f]}:${/\s/.test(String(v)) ? JSON.stringify(String(v)) : v}`

const histOption = computed(() => {
  const h = res.value?.histogram
  if (!h) return {}
  return {
    grid: { left: 40, right: 12, top: 10, bottom: 24 }, tooltip: { trigger: 'axis' },
    xAxis: { type: 'time', axisLine: { lineStyle: { color: '#22395a' } }, axisLabel: { color: '#6b84a6', fontSize: 10 } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#16263d' } }, axisLabel: { color: '#6b84a6', fontSize: 10 } },
    series: [{ type: 'bar', name: 'events', itemStyle: { color: isIds.value ? '#fb923c' : '#22d3ee' }, barMaxWidth: 14, data: h.buckets.map((b) => [b.t * 1000, b.count]) }],
  }
})

// ------------------------------------------------------------------ sources
const sources = ref(null)
const canSources = computed(() => auth.can('blueteam.sources.manage'))
const canDemo = computed(() => auth.can('blueteam.rules.manage'))
async function loadSources() { try { sources.value = await api('/soc/sources') } catch (e) { ui.error(e) } }

const pcapBusy = ref(false)
const pcapInput = ref(null)
async function replayPcap(e) {
  const file = e.target.files?.[0]
  e.target.value = ''
  if (!file) return
  pcapBusy.value = true
  try {
    const form = new FormData()
    form.append('file', file)
    form.append('shift_to_now', 'true')
    const r = await api('/soc/pcap/replay', { method: 'POST', form })
    const s = r.stats || {}
    if (!r.source) ui.error(new Error(r.note || 'Tidak ada lalu lintas yang bisa diekstrak dari pcap ini.'))
    else ui.success(`Replay ${file.name}: ${s.records ?? 0} event (${s.tcp ?? 0} TCP, ${s.udp ?? 0} UDP, ${s.icmp ?? 0} ICMP, ${s.dns ?? 0} DNS, ${s.http ?? 0} HTTP) dari ${s.packets ?? 0} paket → ${r.accepted ?? 0} diterima, ${r.alerts ?? 0} alert. Cari src: alamat penyerang untuk melihatnya.`)
    loadSources()
  } catch (err) { ui.error(err) } finally { pcapBusy.value = false }
}
watch(tab, (t) => { router.replace({ query: { ...route.query, tab: t === 'sources' ? 'sources' : undefined } }); if (t === 'sources') loadSources() })
const srcOpen = ref(false)
const srcForm = reactive({ name: '', kind: 'suricata', description: '' })
function deliverConfig(r, verb) {
  saveTextFile(r.config_filename, r.config)
  ui.success(`${verb}. Konfigurasi shipper beserta ingest key-nya disimpan sebagai ${r.config_filename}; tidak ditampilkan di layar dan tidak dapat diambil kembali.`)
}
async function createSource() {
  try { const r = await api('/soc/sources', { method: 'POST', body: srcForm }); srcOpen.value = false; deliverConfig(r, 'Sumber terdaftar'); srcForm.name = ''; loadSources() } catch (e) { ui.error(e) }
}
const rotateTarget = ref(null)
async function rotate() {
  try { const r = await api(`/soc/sources/${rotateTarget.value.id}/rotate-key`, { method: 'POST' }); rotateTarget.value = null; deliverConfig(r, 'Key dirotasi; key sebelumnya tidak berlaku lagi') } catch (e) { ui.error(e) }
}
async function toggleSource(s) { try { await api(`/soc/sources/${s.id}`, { method: 'PATCH', body: { is_enabled: !s.is_enabled } }); loadSources() } catch (e) { ui.error(e) } }
const up = reactive({ source: null, content: '', filename: '', dataset: '', result: null, busy: false })
async function pickFile(e) {
  const f = e.target.files[0]
  if (!f) return
  if (f.size > 10 * 1024 * 1024) return ui.error('File lebih besar dari 10 MB')
  up.filename = f.name; up.content = await f.text(); up.result = null
}
async function upload() {
  up.busy = true
  try { up.result = await api(`/soc/sources/${up.source.id}/upload`, { method: 'POST', body: { content: up.content, filename: up.filename, dataset: up.dataset || undefined } }); loadSources() }
  catch (e) { ui.error(e) } finally { up.busy = false }
}
async function demo(load) {
  try {
    const r = await api('/soc/demo', { method: load ? 'POST' : 'DELETE' })
    ui.success(load ? `Dataset DEMO dimuat: ${r.accepted} event, ${r.alerts} pembaruan alert` : `Data DEMO dihapus: ${r.events} event, ${r.alerts} alert`)
    loadSources(); search()
  } catch (e) { ui.error(e) }
}
</script>

<template>
  <PageHeader :section="isIds ? 'Blue Team Operations' : 'Blue Team Operations'" :title="isIds ? 'Deteksi Intrusi' : 'SIEM & Analisis Log'"
    :subtitle="isIds ? 'Telemetri IDS dari Suricata, Zeek notice dan Wazuh: signature, penyerang dan target.' : 'Cari event ternormalisasi dari setiap sensor. Klik nilai mana pun untuk pivot.'">
    <div v-if="!isIds" class="flex rounded-md border border-ink-700 p-0.5" role="tablist">
      <button v-for="t in [['search', 'Cari'], ['sources', 'Sumber log']]" :key="t[0]" role="tab" :aria-selected="tab === t[0]"
        :class="['rounded px-3 py-1 text-xs', tab === t[0] ? 'bg-ink-700 text-ink-100' : 'text-ink-400 hover:text-ink-200']" @click="tab = t[0]">{{ t[1] }}</button>
    </div>
  </PageHeader>

  <template v-if="tab === 'search'">
    <form class="panel mb-4 flex flex-wrap items-center gap-2 p-3" @submit.prevent="run">
      <div class="relative min-w-72 flex-1"><Search class="absolute top-2.5 left-3 size-4 text-ink-500" />
        <input v-model="form.q" class="input pl-9 font-mono" placeholder='src:203.0.113.5 outcome:failure sev>=3 -user:root "Failed password"' aria-label="Query" /></div>
      <select v-model="form.range" class="input w-28" aria-label="Rentang waktu" @change="run"><option v-for="(_, k) in RANGES" :key="k" :value="k">Terakhir {{ k }}</option></select>
      <label class="flex items-center gap-1.5 text-xs text-ink-300"><input v-model="form.demo" type="checkbox" class="accent-cyan-400" @change="run" /> sertakan DEMO</label>
      <CrButton type="submit" variant="primary" :loading="loading"><Play class="size-4" /> Cari</CrButton>
    </form>
    <p class="-mt-2 mb-3 text-[11px] text-ink-500">Field: src dst ip port sport user host sig sid cat dataset action outcome proto source · <code>sev&gt;=N</code> · <code>-field:value</code> menegasikan · <code>*</code> wildcard · kata tanpa field mencari di pesan.</p>
    <CrState v-if="err" kind="error" :message="err.message" @retry="search" />
    <CrState v-else-if="!res" kind="loading" />
    <div v-else class="grid gap-4 xl:grid-cols-4">
      <div class="min-w-0 space-y-4 xl:col-span-3">
        <CrPanel :title="`${res.total.toLocaleString()} event`" :subtitle="`${fmtTime(res.from)} → ${fmtTime(res.to)} UTC`">
          <EChart :option="histOption" height="140px" />
        </CrPanel>
        <CrPanel title="Hasil" :padded="false">
          <CrState v-if="!res.items.length" kind="empty" :message="sources && !sources.length ? 'Belum ada sumber log. Daftarkan di Sumber log.' : 'Tidak ada event yang cocok dengan query dan rentang waktu ini.'" />
          <template v-else>
            <div class="overflow-x-auto"><EventTable :items="res.items" @select="selected = $event.id" /></div>
            <div class="border-t border-ink-700/60 p-2"><CrPagination v-model:page="page" :total="res.total" :page-size="res.page_size" /></div>
          </template>
        </CrPanel>
      </div>
      <div class="space-y-4">
        <CrPanel v-for="(vals, f) in res.facets" :key="f" :title="`Top ${f.replace('_', ' ')}`" :padded="false">
          <div v-if="!vals.length" class="px-4 py-3 text-xs text-ink-500">—</div>
          <button v-for="v in vals" :key="v.value" class="flex w-full items-center justify-between gap-2 px-4 py-1.5 text-left hover:bg-ink-800" :data-facet="`${f}=${v.value}`" @click="addTerm(facetTerm(f, v.value))">
            <span class="truncate font-mono text-xs text-ink-200">{{ v.value }}</span><span class="font-mono text-[11px] text-ink-500">{{ v.count }}</span></button>
        </CrPanel>
      </div>
    </div>
    <EventModal :event-id="selected" @close="selected = null" @pivot="pivot" />
  </template>

  <template v-else>
    <div class="mb-3 flex flex-wrap gap-2">
      <CrButton v-if="canSources" variant="primary" @click="srcOpen = true"><Plus class="size-4" /> Daftarkan sumber</CrButton>
      <CrButton v-if="canDemo" @click="demo(true)"><FlaskConical class="size-4" /> Muat dataset DEMO</CrButton>
      <CrButton v-if="canDemo" variant="ghost" @click="demo(false)"><Trash2 class="size-4" /> Hapus data DEMO</CrButton>
      <CrButton v-if="canSources" :loading="pcapBusy" title="Putar ulang file .pcap menjadi event Zeek sehingga rule deteksi diuji terhadap lalu lintas jaringan sungguhan" data-test="replay-pcap" @click="pcapInput?.click()"><Upload class="size-4" /> Replay PCAP</CrButton>
      <input ref="pcapInput" type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" class="hidden" @change="replayPcap">
      <CrButton variant="ghost" @click="loadSources"><RefreshCw class="size-4" /></CrButton>
    </div>
    <CrPanel title="Sumber log" subtitle="Sensor mengirim ke POST /api/v1/soc/ingest dengan header X-Ingest-Key. Key disimpan dalam bentuk hash dan diberikan sekali sebagai file konfigurasi." :padded="false">
      <CrState v-if="!sources" kind="loading" />
      <table v-else class="data-table">
        <thead><tr><th>Sumber</th><th>Format</th><th>Key</th><th>Event</th><th>Event terakhir</th><th>Status</th><th /></tr></thead>
        <tbody>
          <tr v-for="s in sources" :key="s.id" :data-source="s.name">
            <td><div class="flex items-center gap-1.5 text-ink-100"><Database class="size-3.5 text-ink-500" />{{ s.name }} <DemoTag v-if="s.is_demo" /></div><div class="max-w-md truncate text-xs text-ink-500">{{ s.description }}</div></td>
            <td><CrBadge>{{ s.kind }}</CrBadge></td>
            <td class="font-mono text-xs text-ink-400">{{ s.key_prefix ? `${s.key_prefix}…` : 'internal' }}</td>
            <td class="font-mono text-xs">{{ s.events_total.toLocaleString() }}</td>
            <td class="font-mono text-xs text-ink-400">{{ s.last_event_at ? ago(s.last_event_at) : 'never' }}</td>
            <td><CrBadge :tone="s.is_enabled ? 'ok' : 'neutral'">{{ s.is_enabled ? 'enabled' : 'disabled' }}</CrBadge></td>
            <td class="whitespace-nowrap text-right">
              <template v-if="canSources && !s.builtin">
                <CrButton size="sm" variant="ghost" title="Unggah file log" @click="Object.assign(up, { source: s, content: '', filename: '', result: null })"><Upload class="size-3.5" /></CrButton>
                <CrButton size="sm" variant="ghost" title="Rotasi ingest key" @click="rotateTarget = s"><RotateCw class="size-3.5" /></CrButton>
                <CrButton size="sm" variant="ghost" @click="toggleSource(s)">{{ s.is_enabled ? 'Disable' : 'Enable' }}</CrButton>
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </CrPanel>
  </template>

  <CrModal :open="srcOpen" title="Daftarkan sumber log" @close="srcOpen = false">
    <div class="space-y-3">
      <div><label class="field-label" for="src-name">Nama</label><input id="src-name" v-model="srcForm.name" class="input" maxlength="128" placeholder="mis. DMZ Suricata" /></div>
      <div><label class="field-label" for="src-kind">Format</label>
        <select id="src-kind" v-model="srcForm.kind" class="input"><option value="suricata">Suricata EVE JSON</option><option value="zeek">Zeek JSON logs</option><option value="wazuh">Wazuh alerts.json</option><option value="syslog">Syslog (RFC 3164/5424)</option><option value="json">JSON ternormalisasi</option></select></div>
      <div><label class="field-label" for="src-desc">Deskripsi</label><input id="src-desc" v-model="srcForm.description" class="input" /></div>
      <p class="rounded border border-ink-700 bg-ink-950/50 p-2 text-xs text-ink-400">Saat pendaftaran, browser Anda menyimpan file konfigurasi shipper yang berisi ingest key. Key tidak pernah ditampilkan dan tidak dapat diambil kembali; rotasi jika file hilang.</p>
    </div>
    <template #footer><CrButton @click="srcOpen = false">Batal</CrButton><CrButton variant="primary" :disabled="srcForm.name.trim().length < 2" @click="createSource">Daftarkan dan simpan konfigurasi</CrButton></template>
  </CrModal>
  <CrModal :open="!!rotateTarget" title="Rotasi ingest key" @close="rotateTarget = null">
    <p class="text-sm">Terbitkan key baru untuk <b class="text-ink-100">{{ rotateTarget?.name }}</b>? Sensor yang memakai key saat ini langsung tidak diterima lagi.</p>
    <template #footer><CrButton @click="rotateTarget = null">Batal</CrButton><CrButton variant="danger" @click="rotate">Rotasi dan simpan konfigurasi</CrButton></template>
  </CrModal>
  <CrModal :open="!!up.source" :title="`Upload logs to ${up.source?.name}`" @close="up.source = null">
    <div class="space-y-3">
      <input type="file" class="block w-full text-sm text-ink-300 file:mr-3 file:rounded file:border-0 file:bg-ink-700 file:px-3 file:py-1.5 file:text-ink-100" aria-label="File log" @change="pickFile" />
      <p class="text-xs text-ink-500">{{ up.source?.kind === 'syslog' ? 'Satu baris syslog per baris.' : 'NDJSON: one JSON record per line.' }} Mengunggah ulang file yang sama tidak menduplikasi event.</p>
      <div v-if="up.source?.kind === 'zeek'"><label class="field-label" for="up-ds">Tipe log Zeek (jika data tidak memiliki _path)</label><input id="up-ds" v-model="up.dataset" class="input" placeholder="conn, dns, http, ssh, notice…" /></div>
      <div v-if="up.result" class="rounded border border-ink-700 p-2 font-mono text-xs" data-test="upload-result">
        accepted {{ up.result.accepted }} · duplicates {{ up.result.duplicates }} · skipped {{ up.result.skipped }} · rejected {{ up.result.rejected }} · alerts {{ up.result.alerts }}
        <ul v-if="up.result.errors.length" class="mt-1 max-h-32 overflow-y-auto text-sev-high"><li v-for="e in up.result.errors" :key="e.index">#{{ e.index }}: {{ e.reason }}</li></ul>
      </div>
    </div>
    <template #footer><CrButton @click="up.source = null">Tutup</CrButton><CrButton variant="primary" :disabled="!up.content" :loading="up.busy" @click="upload">Ingest {{ up.filename }}</CrButton></template>
  </CrModal>
</template>
