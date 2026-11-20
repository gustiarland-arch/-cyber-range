<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { FileUp, Link2, Play, Plus, Radar, Rss, Trash2, X } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPagination from '@/components/ui/CrPagination.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import SevBadge from '@/components/soc/SevBadge.vue'
import EventModal from '@/components/soc/EventModal.vue'
import { SEVERITIES } from '@/services/soc'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const canManage = computed(() => auth.can('intel.manage'))
const meta = ref(null)
const sources = ref([])
const data = ref(null)
const err = ref(null)
const page = ref(1)
const f = reactive({ q: '', type: '', source_id: '', status: 'active', sighted: false, demo: true })
async function load() {
  try {
    data.value = await api('/intel/indicators', { query: { q: f.q, type: f.type, source_id: f.source_id || undefined, status: f.status, sighted: f.sighted, include_demo: f.demo, page: page.value } })
    err.value = null
  } catch (e) { err.value = e }
}
async function loadSources() { try { sources.value = await api('/intel/sources') } catch (e) { ui.error(e) } }
onMounted(async () => { meta.value = await api('/intel/meta').catch(() => null); loadSources(); load(); if (route.query.id) openInd(Number(route.query.id)) })
watch(() => [f.type, f.source_id, f.status, f.sighted, f.demo], () => { page.value = 1; load() })
watch(page, load)

// ---- detail
const ind = ref(null)
const openEvent = ref(null)
async function openInd(id) {
  try { ind.value = await api(`/intel/indicators/${id}`); router.replace({ query: { ...route.query, id } }) } catch (e) { ui.error(e) }
}
function closeInd() { ind.value = null; const { id: _i, ...q } = route.query; router.replace({ query: q }) }
async function patch(body, msg) {
  try { await api(`/intel/indicators/${ind.value.id}`, { method: 'PATCH', body }); ui.success(msg); openInd(ind.value.id); load() } catch (e) { ui.error(e) }
}
async function delInd() {
  try { await api(`/intel/indicators/${ind.value.id}`, { method: 'DELETE' }); ui.success('Indikator dihapus'); closeInd(); load() } catch (e) { ui.error(e) }
}
const rel = reactive({ value: '', kind: 'related-to', note: '' })
async function addRelation() {
  try {
    const found = await api('/intel/lookup', { query: { value: [rel.value.trim()] } })
    if (!found.length) { ui.error({ message: 'Belum ada indikator dengan nilai itu. Tambahkan terlebih dahulu.' }); return }
    await api(`/intel/indicators/${ind.value.id}/relations`, { method: 'POST', body: { to_id: found[0].id, kind: rel.kind, note: rel.note } })
    ui.success('Relasi ditambahkan'); rel.value = ''; rel.note = ''; openInd(ind.value.id)
  } catch (e) { ui.error(e) }
}
async function delRelation(r) { try { await api(`/intel/relations/${r.id}`, { method: 'DELETE' }); openInd(ind.value.id) } catch (e) { ui.error(e) } }

// ---- add / import / hunt / demo
const add = ref(null)
function newInd() { add.value = { value: '', type: '', confidence: 70, severity: 2, tags: '', description: '', valid_until: '' } }
async function saveInd() {
  const a = add.value
  try {
    const r = await api('/intel/indicators', { method: 'POST', body: { value: a.value, type: a.type || null, confidence: Number(a.confidence), severity: Number(a.severity),
      tags: a.tags.split(',').map((t) => t.trim()).filter(Boolean), description: a.description, valid_until: a.valid_until ? new Date(a.valid_until).toISOString() : null } })
    ui.success(`Indikator disimpan · retro-hunt menemukan ${r.retrohunt.new_sightings} sighting dalam 7 hari`); add.value = null; load(); openInd(r.id)
  } catch (e) { ui.error(e) }
}
const imp = ref(null)
const impResult = ref(null)
function openImport() { imp.value = { source_id: sources.value.find((s) => !s.is_demo)?.id || '', new_source: '', format: 'text', text: '', retrohunt_days: 7 }; impResult.value = null }
async function readImport(e) {
  const file = e.target.files?.[0]
  if (!file) return
  if (file.size > 5_000_000) { ui.error({ message: 'File lebih besar dari 5 MB' }); return }
  imp.value.text = await file.text()
  imp.value.format = /\.json$/i.test(file.name) ? (/"Event"|"Attribute"/.test(imp.value.text.slice(0, 4000)) ? 'misp' : 'stix') : /\.csv$/i.test(file.name) ? 'csv' : 'text'
}
const importing = ref(false)
async function runImport() {
  importing.value = true
  try {
    let sid = imp.value.source_id
    if (sid === 'new') { sid = (await api('/intel/sources', { method: 'POST', body: { name: imp.value.new_source } })).id; await loadSources() }
    impResult.value = await api(`/intel/sources/${sid}/import`, { method: 'POST', body: { format: imp.value.format, text: imp.value.text, retrohunt_days: Number(imp.value.retrohunt_days) } })
    load()
  } catch (e) { ui.error(e) } finally { importing.value = false }
}
const hunting = ref(false)
async function huntAll() {
  hunting.value = true
  try { const r = await api('/intel/retrohunt', { method: 'POST', body: { days: 7 } }); ui.success(`Retro-hunt memindai ${r.scanned} event: ${r.new_sightings} sighting baru, ${r.alerts} alert`); load() } catch (e) { ui.error(e) } finally { hunting.value = false }
}
const hasDemo = computed(() => sources.value.some((s) => s.is_demo))

// scheduled feeds (MISP, TAXII 2.1, STIX/text/CSV URL)
const feedsOpen = ref(false)
const feeds = ref(null)
const feedForm = ref(null)
const feedBusy = ref(null)
const FEED_LABEL = { misp: 'MISP (restSearch)', taxii21: 'TAXII 2.1 collection', stix_url: 'URL bundle STIX 2.1', text_url: 'URL daftar teks', csv_url: 'URL CSV' }
async function loadFeeds() { try { feeds.value = await api('/intel/feeds') } catch (e) { ui.error(e) } }
function openFeeds() { feedsOpen.value = true; feedForm.value = null; loadFeeds() }
function newFeed() { feedForm.value = { name: '', feed_type: 'taxii21', url: '', collection_id: '', auth_scheme: 'none', auth_env: '', interval_minutes: 60, verify_tls: true, default_confidence: 60 } }
async function saveFeed() {
  const b = { ...feedForm.value }
  if (!b.collection_id) delete b.collection_id
  if (b.auth_scheme === 'none') delete b.auth_env
  try { await api('/intel/feeds', { method: 'POST', body: b }); ui.success('Feed dibuat'); feedForm.value = null; loadFeeds(); loadSources() } catch (e) { ui.error(e) }
}
async function runFeed(fd) {
  feedBusy.value = fd.id
  try {
    const r = (await api(`/intel/feeds/${fd.id}/run`, { method: 'POST' })).result
    if (r.status === 'ok') ui.success(`Feed: ${r.created} indikator baru, ${r.updated} diperbarui${r.retrohunt ? `, ${r.retrohunt.new_sightings} sighting` : ''}`)
    else ui.error({ message: `Feed gagal: ${r.error}` })
    loadFeeds(); loadSources(); load()
  } catch (e) { ui.error(e) } finally { feedBusy.value = null }
}
async function toggleFeed(fd) { try { await api(`/intel/feeds/${fd.id}`, { method: 'PATCH', body: { is_enabled: !fd.is_enabled } }); loadFeeds() } catch (e) { ui.error(e) } }
async function delFeed(fd) { try { await api(`/intel/feeds/${fd.id}`, { method: 'DELETE' }); ui.success('Feed dihapus (indikatornya tetap ada)'); loadFeeds() } catch (e) { ui.error(e) } }
async function demo(load_) {
  try {
    const r = await api('/intel/demo', { method: load_ ? 'POST' : 'DELETE' })
    ui.success(load_ ? `Feed DEMO dimuat: ${r.created} indikator, ${r.new_sightings} sighting pada event DEMO` : `DEMO feed removed (${r.indicators} indicators)`)
    loadSources(); load()
  } catch (e) { ui.error(e) }
}
</script>

<template>
  <PageHeader section="Security Intelligence" title="Threat Intelligence" subtitle="Indikator beserta asal-usul dan tingkat keyakinan. Indikator aktif dicocokkan dengan setiap event yang masuk dan telemetri tersimpan (retro-hunt).">
    <template v-if="canManage">
      <CrButton :loading="hunting" @click="huntAll"><Radar class="size-4" /> Retro-hunt 7 hari</CrButton>
      <CrButton data-test="feeds-open" @click="openFeeds"><Rss class="size-4" /> Feed</CrButton>
      <CrButton @click="openImport"><FileUp class="size-4" /> Impor</CrButton>
      <CrButton variant="primary" @click="newInd"><Plus class="size-4" /> Tambah indikator</CrButton>
    </template>
  </PageHeader>
  <form class="panel mb-4 flex flex-wrap items-center gap-2 p-3" @submit.prevent="page = 1; load()">
    <input v-model="f.q" class="input w-72 font-mono" placeholder="nilai atau deskripsi" aria-label="Cari indikator" />
    <select v-model="f.type" class="input w-32" aria-label="Tipe"><option value="">semua tipe</option><option v-for="t in meta?.types || []" :key="t">{{ t }}</option></select>
    <select v-model="f.source_id" class="input w-48" aria-label="Sumber"><option value="">semua sumber</option><option v-for="s in sources" :key="s.id" :value="s.id">{{ s.name }}</option></select>
    <select v-model="f.status" class="input w-28" aria-label="Status"><option value="active">aktif</option><option value="inactive">nonaktif</option><option value="all">semua</option></select>
    <label class="flex items-center gap-1.5 text-xs text-ink-300"><input v-model="f.sighted" type="checkbox" class="accent-cyan-400" /> hanya yang terlihat</label>
    <label class="flex items-center gap-1.5 text-xs text-ink-300"><input v-model="f.demo" type="checkbox" class="accent-cyan-400" /> sertakan DEMO</label>
    <CrButton type="submit">Cari</CrButton>
    <template v-if="canManage"><CrButton v-if="!hasDemo" variant="ghost" class="ml-auto" @click="demo(true)">Muat feed DEMO</CrButton>
      <CrButton v-else variant="ghost" class="ml-auto" @click="demo(false)">Hapus feed DEMO</CrButton></template>
  </form>
  <div class="panel">
    <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
    <CrState v-else-if="!data" kind="loading" />
    <CrState v-else-if="!data.items.length" kind="empty" :message="canManage ? 'Tidak ada indikator yang cocok. Tambahkan, impor feed (teks, CSV atau STIX 2.1) atau muat feed DEMO.' : 'Tidak ada indikator yang cocok.'" />
    <template v-else>
      <table class="data-table" data-test="indicators">
        <thead><tr><th>Indikator</th><th>Tipe</th><th>Sumber</th><th>Tingkat keyakinan</th><th>Severity</th><th>Sightings</th><th>Terakhir terlihat di data</th><th>Status</th></tr></thead>
        <tbody>
          <tr v-for="i in data.items" :key="i.id" class="cursor-pointer" :data-indicator="i.value" @click="openInd(i.id)">
            <td class="max-w-md"><div class="truncate font-mono text-xs text-ink-100">{{ i.value }}</div><div class="flex flex-wrap gap-1"><DemoTag v-if="i.is_demo" /><CrBadge v-for="t in i.tags.filter((x) => x !== 'DEMO')" :key="t">{{ t }}</CrBadge></div></td>
            <td><CrBadge>{{ i.type }}</CrBadge></td>
            <td class="text-xs">{{ i.source }}</td>
            <td><div class="flex items-center gap-2"><div class="h-1.5 w-16 rounded bg-ink-700"><div class="h-1.5 rounded bg-accent-400" :style="{ width: `${i.confidence}%` }" /></div><span class="font-mono text-[11px]">{{ i.confidence }}</span></div></td>
            <td><SevBadge :sev="i.severity" /></td>
            <td class="font-mono text-xs" :class="i.sightings_count ? 'text-warn' : 'text-ink-500'">{{ i.sightings_count }}</td>
            <td class="font-mono text-[11px] text-ink-400">{{ i.last_sighted_at ? ago(i.last_sighted_at) : '—' }}</td>
            <td><CrBadge :tone="i.is_active ? 'ok' : 'neutral'">{{ i.is_active ? 'active' : 'inactive' }}</CrBadge></td>
          </tr>
        </tbody>
      </table>
      <CrPagination v-model:page="page" :total="data.total" :page-size="data.page_size" />
    </template>
  </div>

  <CrModal :open="!!ind" :title="ind ? `${ind.type} · ${ind.value}` : ''" width="max-w-4xl" @close="closeInd">
    <div v-if="ind" class="space-y-4 text-sm" data-test="indicator-detail">
      <div class="flex flex-wrap items-center gap-2"><SevBadge :sev="ind.severity" /><CrBadge :tone="ind.is_active ? 'ok' : 'neutral'">{{ ind.is_active ? 'active' : 'inactive' }}</CrBadge><DemoTag v-if="ind.is_demo" />
        <span class="text-xs text-ink-400">source <b class="text-ink-200">{{ ind.source }}</b> · confidence {{ ind.confidence }} · first {{ fmtTime(ind.first_seen) }} · refreshed {{ ago(ind.last_seen) }}<span v-if="ind.valid_until"> · berlaku hingga {{ fmtTime(ind.valid_until) }}</span></span></div>
      <p v-if="ind.description" class="text-xs text-ink-300">{{ ind.description }}</p>
      <div v-if="canManage && !ind.is_demo" class="flex flex-wrap items-center gap-2">
        <label class="text-xs text-ink-400" for="ind-conf">confidence</label><input id="ind-conf" type="number" min="0" max="100" class="input w-20" :value="ind.confidence" @change="patch({ confidence: Number($event.target.value) }, 'Tingkat keyakinan diperbarui')" />
        <label class="text-xs text-ink-400" for="ind-sev">severity</label><select id="ind-sev" class="input w-28" :value="ind.severity" @change="patch({ severity: Number($event.target.value) }, 'Severity diperbarui')"><option v-for="(s, i) in SEVERITIES" :key="s" :value="i">{{ s }}</option></select>
        <CrButton size="sm" @click="patch({ is_active: !ind.is_active }, ind.is_active ? 'Indikator dinonaktifkan' : 'Indikator diaktifkan kembali')">{{ ind.is_active ? 'Deactivate' : 'Reactivate' }}</CrButton>
        <CrButton v-if="!ind.sightings_count" size="sm" variant="danger" @click="delInd"><Trash2 class="size-3.5" /> Hapus</CrButton>
      </div>
      <div v-if="ind.other_sources.length" class="text-xs text-ink-400">Juga dilaporkan oleh: <span v-for="o in ind.other_sources" :key="o.id" class="mr-2"><b class="text-ink-200">{{ o.source }}</b> ({{ o.confidence }})</span></div>
      <section>
        <h4 class="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-400">Sightings ({{ ind.sightings_count }})</h4>
        <p v-if="!ind.sightings_visible" class="text-xs text-ink-500">Detail event memerlukan izin blueteam.alerts.view.</p>
        <p v-else-if="!ind.sightings.length" class="text-xs text-ink-500">Tidak teramati di telemetri tersimpan.</p>
        <table v-else class="data-table" data-test="sightings"><thead><tr><th>Terlihat</th><th>Cocok di</th><th>Event</th><th>Melalui</th></tr></thead>
          <tbody><tr v-for="s in ind.sightings" :key="s.id" class="cursor-pointer" @click="openEvent = s.event.id"><td class="font-mono text-[11px]">{{ fmtTime(s.seen_at) }}</td><td><CrBadge>{{ s.field }}</CrBadge></td>
            <td class="text-xs"><span class="font-mono text-ink-400">{{ s.event.dataset }}</span> {{ s.event.src_ip }} → {{ s.event.dst_ip }}{{ s.event.dst_port ? `:${s.event.dst_port}` : '' }} <span class="text-ink-500">{{ s.event.message }}</span> <DemoTag v-if="s.is_demo" /></td>
            <td class="text-xs">{{ s.via }}</td></tr></tbody></table>
        <div v-if="ind.alert_ids?.length" class="mt-1 text-xs">Alert: <RouterLink v-for="a in ind.alert_ids" :key="a" :to="{ name: 'incident-response', query: { alert: a } }" class="mr-2 text-accent-300 hover:underline">#{{ a }}</RouterLink></div>
      </section>
      <section>
        <h4 class="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-400">Relasi</h4>
        <ul class="space-y-1 text-xs"><li v-for="r in ind.relations" :key="r.id" class="flex items-center gap-2"><Link2 class="size-3 text-ink-500" />
          <span>{{ r.direction === 'out' ? 'this' : r.other.value }} <b>{{ r.kind }}</b> {{ r.direction === 'out' ? r.other.value : 'this' }}</span><span class="text-ink-500">{{ r.note }}</span>
          <button class="text-ink-400 hover:underline" @click="openInd(r.other.id)">open</button><button v-if="canManage" class="text-ink-500 hover:text-sev-critical" title="Hapus" @click="delRelation(r)"><X class="size-3" /></button></li>
          <li v-if="!ind.relations.length" class="text-ink-500">Belum ada yang tercatat.</li></ul>
        <form v-if="canManage" class="mt-2 flex flex-wrap gap-2" @submit.prevent="addRelation">
          <select v-model="rel.kind" class="input w-44" aria-label="Relasi"><option v-for="k in meta?.relation_kinds || []" :key="k">{{ k }}</option></select>
          <input v-model="rel.value" class="input w-56 font-mono text-xs" placeholder="nilai indikator lain" aria-label="Indikator terkait" />
          <input v-model="rel.note" class="input flex-1" placeholder="note" aria-label="Catatan relasi" /><CrButton type="submit" size="sm" :disabled="!rel.value.trim()">Link</CrButton></form>
      </section>
    </div>
  </CrModal>

  <CrModal :open="!!add" title="Tambah indikator" width="max-w-xl" @close="add = null">
    <div v-if="add" class="grid gap-3 md:grid-cols-2">
      <div class="md:col-span-2"><label class="field-label" for="ti-val">Nilai</label><input id="ti-val" v-model="add.value" class="input font-mono" placeholder="IP, CIDR, domain, URL, hash atau email" /></div>
      <div><label class="field-label" for="ti-type">Tipe</label><select id="ti-type" v-model="add.type" class="input"><option value="">deteksi otomatis</option><option v-for="t in meta?.types || []" :key="t">{{ t }}</option></select></div>
      <div><label class="field-label" for="ti-valid">Berlaku hingga (opsional)</label><input id="ti-valid" v-model="add.valid_until" type="datetime-local" class="input" /></div>
      <div><label class="field-label" for="ti-conf">Tingkat keyakinan (0-100)</label><input id="ti-conf" v-model="add.confidence" type="number" min="0" max="100" class="input" /></div>
      <div><label class="field-label" for="ti-sev">Severity</label><select id="ti-sev" v-model="add.severity" class="input"><option v-for="(s, i) in SEVERITIES" :key="s" :value="i">{{ s }}</option></select></div>
      <div class="md:col-span-2"><label class="field-label" for="ti-tags">Tags</label><input id="ti-tags" v-model="add.tags" class="input" placeholder="c2, phishing" /></div>
      <div class="md:col-span-2"><label class="field-label" for="ti-desc">Deskripsi / asal-usul</label><textarea id="ti-desc" v-model="add.description" class="input" rows="2" /></div>
      <p class="text-xs text-ink-500 md:col-span-2">Disimpan ke "Analyst submissions". Tingkat keyakinan di bawah 30 mencatat sighting tanpa memunculkan alert.</p>
    </div>
    <template #footer><CrButton @click="add = null">Batal</CrButton><CrButton variant="primary" :disabled="!add?.value.trim()" @click="saveInd">Simpan dan retro-hunt</CrButton></template>
  </CrModal>

  <CrModal :open="!!imp" title="Impor indikator" width="max-w-3xl" @close="imp = null">
    <div v-if="imp" class="space-y-3">
      <div class="grid gap-3 md:grid-cols-3">
        <div><label class="field-label" for="imp-src">Ke sumber</label><select id="imp-src" v-model="imp.source_id" class="input"><option v-for="s in sources.filter((x) => !x.is_demo)" :key="s.id" :value="s.id">{{ s.name }}</option><option value="new">+ sumber baru…</option></select></div>
        <div v-if="imp.source_id === 'new'"><label class="field-label" for="imp-new">Nama sumber baru</label><input id="imp-new" v-model="imp.new_source" class="input" /></div>
        <div><label class="field-label" for="imp-fmt">Format</label><select id="imp-fmt" v-model="imp.format" class="input"><option value="text">teks (satu per baris)</option><option value="csv">CSV (header: value,type,confidence,severity,tags,description,valid_until)</option><option value="stix">STIX 2.1 bundle (JSON)</option><option value="misp">MISP event / restSearch (JSON)</option></select></div>
        <div><label class="field-label" for="imp-days">Hari retro-hunt</label><input id="imp-days" v-model="imp.retrohunt_days" type="number" min="0" max="90" class="input" /></div>
      </div>
      <div><div class="mb-1 flex justify-between"><label class="field-label !mb-0" for="imp-text">Konten</label><label class="flex cursor-pointer items-center gap-1 text-xs text-accent-300 hover:underline"><FileUp class="size-3.5" /> Muat file<input type="file" class="hidden" accept=".txt,.csv,.json" aria-label="File indikator" @change="readImport" /></label></div>
        <textarea id="imp-text" v-model="imp.text" class="input font-mono text-xs" rows="10" placeholder="198.51.100.9&#10;evil[.]example&#10;hxxp://bad.example/payload" /></div>
      <div v-if="impResult" class="rounded border border-ink-700 p-3 text-xs" data-test="import-result">
        Parsed {{ impResult.parsed }} · created {{ impResult.created }} · updated {{ impResult.updated }}<span v-if="impResult.retrohunt"> · retro-hunt: {{ impResult.retrohunt.new_sightings }} sighting(s), {{ impResult.retrohunt.alerts }} alert(s) over {{ impResult.retrohunt.scanned }} event</span>
        <ul v-if="impResult.errors.length" class="mt-2 list-disc pl-5 text-sev-high"><li v-for="e in impResult.errors" :key="e">{{ e }}</li></ul>
      </div>
    </div>
    <template #footer><CrButton @click="imp = null">Tutup</CrButton><CrButton variant="primary" :loading="importing" :disabled="!imp?.text.trim() || !imp?.source_id || (imp?.source_id === 'new' && imp?.new_source.trim().length < 3)" @click="runImport">Impor</CrButton></template>
  </CrModal>
  <EventModal :event-id="openEvent" @close="openEvent = null" @pivot="(q) => router.push({ name: 'siem', query: { q } })" />
  <CrModal :open="feedsOpen" title="Feed threat intel terjadwal" width="max-w-5xl" @close="feedsOpen = false">
    <p class="mb-3 text-xs text-ink-400">Feed ditarik otomatis sesuai interval (dicek tiap 5 menit) dan hanya mengambil data baru sejak penarikan terakhir. Kunci API tidak pernah disimpan di database:
      tulis nama variabel lingkungan (mis. <code>CR_FEED_MISP_KEY</code>) dan isi nilainya di file <code>.env</code> server. Alamat LAN/privat
      {{ feeds?.allow_private ? 'diizinkan' : 'ditolak (set CR_INTEL_FEED_ALLOW_PRIVATE=true untuk MISP internal)' }}.</p>
    <CrState v-if="!feeds" kind="loading" />
    <template v-else>
      <CrState v-if="!feeds.feeds.length && !feedForm" kind="empty" message="Belum ada feed. Tambahkan server MISP, collection TAXII 2.1 atau URL feed STIX/teks/CSV." />
      <table v-if="feeds.feeds.length" class="data-table mb-3" data-test="feeds">
        <thead><tr><th>Feed</th><th>Tipe</th><th>Interval</th><th>Terakhir</th><th>Status</th><th /></tr></thead>
        <tbody><tr v-for="fd in feeds.feeds" :key="fd.id">
          <td><div class="text-ink-100">{{ fd.source }}</div><div class="max-w-xs truncate font-mono text-[11px] text-ink-500">{{ fd.url }}{{ fd.collection_id ? ` · ${fd.collection_id}` : '' }}</div>
            <div v-if="fd.auth_scheme !== 'none'" :class="['text-[11px]', fd.auth_configured ? 'text-ink-500' : 'text-warn']">kunci: {{ fd.auth_env }} {{ fd.auth_configured ? '(terpasang)' : '(belum diisi di server)' }}</div></td>
          <td class="text-xs">{{ FEED_LABEL[fd.feed_type] }}</td><td class="font-mono text-xs">{{ fd.interval_minutes }} mnt</td>
          <td class="text-xs">{{ fd.last_run_at ? ago(fd.last_run_at) : 'belum' }}<div v-if="fd.last_run_at" class="text-ink-500">{{ fd.last_count }} indikator</div></td>
          <td><CrBadge :tone="!fd.is_enabled ? 'neutral' : fd.last_status === 'error' ? 'bad' : fd.last_status === 'ok' ? 'ok' : 'accent'">{{ !fd.is_enabled ? 'nonaktif' : fd.last_status === 'error' ? 'gagal' : fd.last_status === 'ok' ? 'ok' : 'menunggu' }}</CrBadge>
            <div v-if="fd.last_error" class="mt-1 max-w-xs text-[11px] text-sev-critical">{{ $tr(fd.last_error) }}</div></td>
          <td class="whitespace-nowrap text-right"><CrButton size="sm" variant="ghost" :loading="feedBusy === fd.id" title="Tarik sekarang" @click="runFeed(fd)"><Play class="size-3.5" /></CrButton>
            <CrButton size="sm" variant="ghost" @click="toggleFeed(fd)">{{ fd.is_enabled ? 'Nonaktifkan' : 'Aktifkan' }}</CrButton>
            <CrButton size="sm" variant="ghost" title="Hapus feed" @click="delFeed(fd)"><Trash2 class="size-3.5" /></CrButton></td>
        </tr></tbody>
      </table>
      <div v-if="feedForm" class="grid grid-cols-2 gap-3 rounded border border-ink-700 p-3 md:grid-cols-4" data-test="feed-form">
        <div class="col-span-2"><label class="field-label" for="fd-name">Nama sumber</label><input id="fd-name" v-model="feedForm.name" class="input" /></div>
        <div class="col-span-2"><label class="field-label" for="fd-type">Tipe</label><select id="fd-type" v-model="feedForm.feed_type" class="input"><option v-for="(l, k) in FEED_LABEL" :key="k" :value="k">{{ l }}</option></select></div>
        <div class="col-span-2 md:col-span-3"><label class="field-label" for="fd-url">{{ feedForm.feed_type === 'taxii21' ? 'URL API root TAXII' : feedForm.feed_type === 'misp' ? 'URL server MISP' : 'URL feed' }}</label>
          <input id="fd-url" v-model="feedForm.url" class="input font-mono" :placeholder="feedForm.feed_type === 'taxii21' ? 'https://taxii.example.org/api1' : feedForm.feed_type === 'misp' ? 'https://misp.example.org' : 'https://…'" /></div>
        <div v-if="feedForm.feed_type === 'taxii21'"><label class="field-label" for="fd-col">ID collection</label><input id="fd-col" v-model="feedForm.collection_id" class="input font-mono" /></div>
        <div><label class="field-label" for="fd-auth">Autentikasi</label><select id="fd-auth" v-model="feedForm.auth_scheme" class="input"><option value="none">tanpa</option><option value="misp">MISP (Authorization: key)</option><option value="bearer">Bearer token</option><option value="basic">Basic (user:password)</option></select></div>
        <div v-if="feedForm.auth_scheme !== 'none'"><label class="field-label" for="fd-env">Variabel lingkungan</label><input id="fd-env" v-model="feedForm.auth_env" class="input font-mono" placeholder="CR_FEED_MISP_KEY" /></div>
        <div><label class="field-label" for="fd-int">Interval (menit)</label><input id="fd-int" v-model.number="feedForm.interval_minutes" type="number" min="5" class="input" /></div>
        <div><label class="field-label" for="fd-conf">Keyakinan default</label><input id="fd-conf" v-model.number="feedForm.default_confidence" type="number" min="0" max="100" class="input" /></div>
        <label class="flex items-center gap-2 self-end text-sm"><input v-model="feedForm.verify_tls" type="checkbox" /> Verifikasi TLS</label>
      </div>
    </template>
    <template #footer>
      <CrButton v-if="!feedForm" class="mr-auto" @click="newFeed"><Plus class="size-4" /> Feed baru</CrButton>
      <template v-else><CrButton @click="feedForm = null">Batal</CrButton><CrButton variant="primary" :disabled="feedForm.name.trim().length < 3 || feedForm.url.length < 8" @click="saveFeed">Simpan feed</CrButton></template>
    </template>
  </CrModal>
</template>
