<script setup>
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Copy, FlaskConical, FolderPlus, RefreshCw, Share2 } from 'lucide-vue-next'
import { api } from '@/services/api'
import { fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SevBadge from '@/components/soc/SevBadge.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import { SAMPLE_STATUS_TONE, VERDICT_TONE, fmtBytes } from '@/components/malware/mw'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const s = ref(null)
const err = ref(null)
const meta = ref(null)
let poll = null
async function load() {
  try { s.value = await api(`/malware/samples/${route.params.id}`); err.value = null } catch (e) { err.value = e; return }
  clearInterval(poll)
  if (['quarantined', 'analyzing'].includes(s.value.status) || s.value.sandbox_runs.some((r) => ['submitted', 'running'].includes(r.status))) poll = setInterval(load, 3000)
}
watch(() => route.params.id, async () => { meta.value = meta.value || (await api('/malware/meta').catch(() => null)); load() }, { immediate: true })
onBeforeUnmount(() => clearInterval(poll))
const st = computed(() => s.value?.static || {})
const iocs = computed(() => st.value.iocs || { urls: [], ips: [], domains: [], emails: [], registry: [] })
const intelHits = computed(() => new Set([...(st.value.intel?.ioc_matches || []).map((i) => i.value)]))
function copy(v) { navigator.clipboard?.writeText(v).then(() => ui.success('Copied'), () => {}) }

const v = reactive({ verdict: '', note: '' })
watch(s, (x) => { if (x && !v.verdict) { v.verdict = x.verdict; v.note = x.verdict_note } })
async function saveVerdict() {
  try { s.value = await api(`/malware/samples/${s.value.id}/verdict`, { method: 'POST', body: { verdict: v.verdict, note: v.note } }); ui.success('Verdict dicatat') } catch (e) { ui.error(e) }
}
async function reanalyse() { try { await api(`/malware/samples/${s.value.id}/reanalyse`, { method: 'POST' }); ui.success('Analisis ulang masuk antrean'); load() } catch (e) { ui.error(e) } }

const promote = ref(null)
function openPromote() { promote.value = { confidence: 70, severity: 3, iocs: [] } }
async function doPromote() {
  try {
    const r = await api(`/malware/samples/${s.value.id}/intel`, { method: 'POST', body: { ...promote.value, confidence: Number(promote.value.confidence), severity: Number(promote.value.severity) } })
    ui.success(`${r.ids.length} indikator di threat intel · retro-hunt: ${r.new_sightings} sighting`); promote.value = null; load()
  } catch (e) { ui.error(e) }
}
const sbx = ref(null)
async function doSandbox() {
  try { await api(`/malware/samples/${s.value.id}/sandbox`, { method: 'POST', body: { ...sbx.value, timeout_seconds: Number(sbx.value.timeout_seconds) } }); ui.success('Dikirim ke sandbox terisolasi'); sbx.value = null; load() } catch (e) { ui.error(e) }
}
async function refreshRun(r) { try { await api(`/malware/sandbox-runs/${r.id}/refresh`, { method: 'POST' }); load() } catch (e) { ui.error(e) } }

const toCase = ref(null)
const cases = ref([])
async function openToCase() { cases.value = await api('/forensics/cases').catch(() => []); toCase.value = { case_id: cases.value[0]?.id || '', title: '', location: '' } }
async function doToCase() {
  try { const e = await api(`/forensics/cases/${toCase.value.case_id}/evidence/sample`, { method: 'POST', body: { sample_id: s.value.id, title: toCase.value.title, location: toCase.value.location } })
    ui.success(`Ditambahkan sebagai evidence ${e.reference}`); toCase.value = null; load() } catch (e) { ui.error(e) }
}
const showStrings = ref(false)
</script>

<template>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!s" kind="loading" />
  <template v-else>
    <PageHeader section="Analisis Malware" :title="s.filenames[0] || s.sha256" :subtitle="`${s.file_type_label} · ${s.type_detail} · ${fmtBytes(s.size)}`">
      <CrButton variant="ghost" @click="router.push({ name: 'malware' })"><ArrowLeft class="size-4" /> Sampel</CrButton>
      <CrButton v-if="auth.can('malware.submit')" :disabled="s.status === 'analyzing'" @click="reanalyse"><RefreshCw class="size-4" /> Analisis ulang</CrButton>
      <CrButton v-if="auth.can('evidence.manage')" @click="openToCase"><FolderPlus class="size-4" /> Tambah ke kasus</CrButton>
      <CrButton v-if="auth.can('intel.manage')" :disabled="!['suspicious', 'malicious'].includes(s.verdict)" :title="['suspicious', 'malicious'].includes(s.verdict) ? '' : 'Catat verdict suspicious/malicious terlebih dahulu'" data-test="promote" @click="openPromote"><Share2 class="size-4" /> Promosikan ke intel</CrButton>
    </PageHeader>
    <div class="grid gap-4 lg:grid-cols-3" data-test="sample-detail">
      <div class="panel space-y-2 p-4 text-sm lg:col-span-2">
        <div class="flex flex-wrap items-center gap-2"><CrBadge :tone="SAMPLE_STATUS_TONE[s.status]" data-test="sample-status">{{ $st(s.status) }}</CrBadge><CrBadge :tone="VERDICT_TONE[s.verdict]" data-test="sample-verdict">verdict: {{ s.verdict }}</CrBadge>
          <CrBadge v-for="t in s.tags" :key="t">{{ t }}</CrBadge><span class="text-xs text-ink-400">submitted {{ s.submissions }}× · pertama oleh {{ s.submitted_by }} {{ fmtTime(s.created_at) }}</span></div>
        <div v-for="h in ['sha256', 'sha1', 'md5']" :key="h" class="flex items-center gap-2 font-mono text-xs"><span class="w-14 uppercase text-ink-500">{{ h }}</span><span class="break-all text-ink-200" :data-hash="h">{{ s[h] }}</span>
          <button class="text-ink-500 hover:text-ink-200" :aria-label="`Copy ${h}`" @click="copy(s[h])"><Copy class="size-3" /></button></div>
        <div class="text-xs text-ink-400">Names: {{ s.filenames.join(', ') }} · entropy {{ s.entropy.toFixed(2) }}/8<span v-if="s.source_note"> · source: {{ s.source_note }}</span>
          <span v-if="s.incident_id"> · <RouterLink :to="{ name: 'incident-detail', params: { id: s.incident_id } }" class="text-accent-300 hover:underline">incident #{{ s.incident_id }}</RouterLink></span></div>
        <p v-if="s.analysis_error" class="text-xs text-sev-critical">{{ s.analysis_error }}</p>
        <ul v-if="st.observations?.length" class="space-y-1" data-test="observations"><li v-for="(o, i) in st.observations" :key="i" class="rounded border border-ink-700 px-2 py-1 text-xs"><CrBadge>{{ o.kind }}</CrBadge> {{ o.text }}</li></ul>
        <div v-if="st.entropy_blocks?.length"><div class="field-label">Entropi per region</div>
          <div class="flex h-10 items-end gap-px" aria-label="Entropi per region"><div v-for="(e, i) in st.entropy_blocks" :key="i" class="flex-1 rounded-t" :class="e > 7.2 ? 'bg-sev-high' : 'bg-accent-500/60'" :style="{ height: `${(e / 8) * 100}%` }" :title="e.toFixed(2)" /></div></div>
      </div>
      <div class="panel space-y-2 p-4 text-sm">
        <h3 class="text-sm font-semibold text-ink-100">Verdict analis</h3>
        <p class="text-xs text-ink-500">Hanya manusia yang memutuskan. Kutip evidence-nya (hit YARA, IOC, perilaku sandbox).</p>
        <template v-if="auth.can('malware.submit')">
          <select v-model="v.verdict" class="input" aria-label="Verdict" data-test="verdict-select"><option v-for="x in meta?.verdicts || []" :key="x">{{ x }}</option></select>
          <textarea v-model="v.note" class="input" rows="3" placeholder="Evidence pendukung verdict" aria-label="Catatan verdict" data-test="verdict-note" />
          <CrButton :disabled="v.verdict !== 'unknown' && v.note.trim().length < 10" data-test="save-verdict" @click="saveVerdict">Catat verdict</CrButton>
        </template>
        <p v-if="s.verdict_by" class="text-xs text-ink-400">{{ s.verdict }} oleh {{ s.verdict_by }} · {{ fmtTime(s.verdict_at) }}<br>{{ s.verdict_note }}</p>
      </div>

      <div class="panel p-4 lg:col-span-2">
        <h3 class="mb-2 text-sm font-semibold text-ink-100">Kecocokan YARA <span class="text-xs font-normal text-ink-500">hit signature, bukan verdict</span></h3>
        <p v-if="!s.yara.length" class="text-xs text-ink-500">{{ s.status === 'analyzed' ? 'Tidak ada rule aktif yang cocok.' : 'Menunggu analisis.' }}</p>
        <div v-for="m in s.yara" :key="m.id" class="mb-2 rounded border border-ink-700 p-2 text-xs" data-test="yara-match">
          <div class="flex flex-wrap items-center gap-2"><SevBadge :sev="m.severity" /><b class="font-mono text-ink-100">{{ m.rule }}</b><span class="text-ink-500">{{ m.ruleset }}</span><CrBadge v-if="m.stale" tone="warn">rule berubah sejak</CrBadge></div>
          <div v-if="m.meta.description" class="mt-1 text-ink-300">{{ m.meta.description }}</div>
          <div class="mt-1 flex flex-wrap gap-2 font-mono text-[11px] text-ink-400"><span v-for="(x, i) in m.strings" :key="i">{{ x.id }}@{{ x.offset }} <span class="text-ink-500">{{ x.preview_hex }}</span></span></div>
        </div>
      </div>
      <div class="panel p-4">
        <h3 class="mb-2 text-sm font-semibold text-ink-100">Threat intel</h3>
        <p class="text-xs text-ink-400">Hash matches: {{ st.intel?.hash_matches?.length || 0 }} · IOC matches: {{ st.intel?.ioc_matches?.length || 0 }}</p>
        <ul class="mt-1 space-y-1 text-xs"><li v-for="i in [...(st.intel?.hash_matches || []), ...(st.intel?.ioc_matches || [])]" :key="i.id">
          <RouterLink :to="{ name: 'threat-intel', query: { id: i.id } }" class="font-mono text-accent-300 hover:underline">{{ i.type }} {{ i.value }}</RouterLink> <SevBadge :sev="i.severity" /> <DemoTag v-if="i.is_demo" /></li></ul>
        <p v-if="s.intel_indicator_ids.length" class="mt-2 text-xs text-ok">SHA-256 sampel ini adalah indikator di threat intel.</p>
      </div>

      <div class="panel p-4 lg:col-span-2">
        <h3 class="mb-2 text-sm font-semibold text-ink-100">Kandidat IOC yang diekstrak <span class="text-xs font-normal text-ink-500">dari strings; tidak divalidasi</span></h3>
        <div class="grid gap-3 md:grid-cols-2" data-test="iocs">
          <div v-for="k in ['urls', 'domains', 'ips', 'emails', 'registry']" :key="k"><div class="field-label">{{ k }} ({{ iocs[k]?.length || 0 }})</div>
            <ul class="max-h-36 overflow-y-auto font-mono text-[11px]"><li v-for="x in iocs[k] || []" :key="x" class="break-all" :class="intelHits.has(x) ? 'text-sev-high' : 'text-ink-300'">{{ x }}<span v-if="intelHits.has(x)"> ← intel</span></li></ul></div>
        </div>
        <div class="mt-3"><button class="text-xs text-accent-300 hover:underline" @click="showStrings = !showStrings">{{ showStrings ? 'Hide' : 'Tampilkan' }} strings ({{ st.strings?.total || 0 }}: {{ st.strings?.ascii || 0 }} ASCII, {{ st.strings?.wide || 0 }} UTF-16)</button>
          <pre v-if="showStrings" class="mt-2 max-h-72 overflow-auto rounded bg-ink-950/70 p-2 text-[11px] text-ink-300">{{ (st.strings?.sample || []).join('\n') }}</pre></div>
      </div>
      <div class="panel p-4">
        <h3 class="mb-2 text-sm font-semibold text-ink-100">Headers</h3>
        <template v-if="st.pe && !st.pe.error"><div class="space-y-0.5 font-mono text-[11px] text-ink-300"><div>machine {{ st.pe.machine }} · {{ st.pe.is_dll ? 'DLL' : 'EXE' }} · subsystem {{ st.pe.subsystem }}</div>
          <div>compiled (header) {{ st.pe.timestamp ? new Date(st.pe.timestamp * 1000).toISOString() : '—' }}</div><div>entry {{ st.pe.entry_point }} · base {{ st.pe.image_base }}</div><div v-if="st.pe.imphash">imphash {{ st.pe.imphash }}</div></div>
          <table class="data-table mt-2"><thead><tr><th>Bagian</th><th>Raw</th><th>Entropy</th><th>Flags</th></tr></thead><tbody><tr v-for="x in st.pe.sections" :key="x.name"><td class="font-mono text-xs">{{ x.name }}</td><td class="text-xs">{{ x.raw_size }}</td>
            <td class="text-xs" :class="x.entropy > 7.2 ? 'text-sev-high' : ''">{{ x.entropy }}</td><td class="text-xs">{{ x.executable ? 'X' : '' }}{{ x.writable ? 'W' : '' }}</td></tr></tbody></table>
          <div v-if="st.pe.suspicious_imports.length" class="mt-2 text-xs"><div class="field-label">Import yang menarik</div><div v-for="x in st.pe.suspicious_imports" :key="x.api" class="font-mono text-[11px]">{{ x.api }} <span class="text-ink-500">{{ x.why }}</span></div></div></template>
        <p v-else-if="st.pe?.error" class="text-xs text-sev-high">{{ st.pe.error }}</p>
        <div v-else-if="st.elf" class="font-mono text-[11px] text-ink-300">{{ st.elf.class }} · {{ st.elf.endianness }} · {{ st.elf.type }} · {{ st.elf.machine }}</div>
        <p v-else class="text-xs text-ink-500">Tidak ada header executable untuk tipe ini.</p>
      </div>

      <div class="panel p-4 lg:col-span-2">
        <div class="mb-2 flex items-center gap-2"><h3 class="text-sm font-semibold text-ink-100">Analisis dinamis (sandbox terisolasi)</h3>
          <CrButton v-if="auth.can('malware.sandbox.submit')" size="sm" class="ml-auto" :disabled="!meta?.sandbox.available" data-test="sandbox-btn"
            @click="sbx = { justification: '', timeout_seconds: 120, acknowledge_isolation: false }"><FlaskConical class="size-3.5" /> Kirim ke sandbox</CrButton></div>
        <p v-if="!meta?.sandbox.available" class="text-xs text-ink-400" data-test="sandbox-off">{{ meta?.sandbox.reason }}</p>
        <div v-for="r in s.sandbox_runs" :key="r.id" class="mb-2 rounded border border-ink-700 p-2 text-xs">
          <div class="flex flex-wrap items-center gap-2"><CrBadge :tone="r.status === 'reported' ? 'ok' : r.status === 'failed' ? 'critical' : 'accent'">{{ $st(r.status) }}</CrBadge><span>{{ r.provider }} task {{ r.external_id || '—' }} · network {{ r.network }} · {{ r.timeout_seconds }} dtk · oleh {{ r.submitted_by }} {{ fmtTime(r.submitted_at) }}</span>
            <CrButton v-if="['submitted', 'running'].includes(r.status)" size="sm" variant="ghost" @click="refreshRun(r)">Muat ulang</CrButton></div>
          <p v-if="r.error" class="text-sev-critical">{{ r.error }}</p>
          <div v-if="r.summary?.signatures" class="mt-1">score {{ r.summary.score ?? '—' }} · machine {{ r.summary.machine }} · {{ r.summary.signatures.length }} signature(s): {{ r.summary.signatures.map((x) => x.name).join(', ') }}</div>
        </div>
      </div>
      <div class="panel p-4">
        <h3 class="mb-2 text-sm font-semibold text-ink-100">Evidence & riwayat</h3>
        <ul v-if="s.evidence.length" class="mb-2 text-xs"><li v-for="e in s.evidence" :key="e.id"><RouterLink :to="{ name: 'evidence', params: { id: e.id } }" class="text-accent-300 hover:underline">{{ e.title }}</RouterLink></li></ul>
        <ol class="max-h-64 space-y-1 overflow-y-auto text-xs"><li v-for="h in s.history" :key="h.id"><span class="font-mono text-ink-500">{{ fmtTime(h.at) }}</span> <CrBadge>{{ $st(h.kind) }}</CrBadge> {{ $tr(h.message) }}</li></ol>
      </div>
    </div>

    <CrModal :open="!!promote" title="Promosikan ke threat intelligence" width="max-w-xl" @close="promote = null">
      <div v-if="promote" class="space-y-3 text-sm">
        <p class="text-xs text-ink-400">Menambahkan SHA-256 dan IOC yang Anda centang ke sumber "Malware analysis (platform)", lalu melakukan retro-hunt pada telemetri 30 hari.</p>
        <div class="grid grid-cols-2 gap-3"><div><label class="field-label" for="pr-conf">Tingkat keyakinan</label><input id="pr-conf" v-model="promote.confidence" type="number" min="0" max="100" class="input" /></div>
          <div><label class="field-label" for="pr-sev">Severity</label><input id="pr-sev" v-model="promote.severity" type="number" min="0" max="4" class="input" /></div></div>
        <div class="max-h-56 overflow-y-auto rounded border border-ink-700 p-2"><label v-for="x in [...iocs.domains, ...iocs.ips, ...iocs.urls]" :key="x" class="flex items-center gap-2 font-mono text-[11px]">
          <input v-model="promote.iocs" type="checkbox" :value="x" class="accent-cyan-400" />{{ x }}</label><p v-if="!iocs.domains.length && !iocs.ips.length && !iocs.urls.length" class="text-xs text-ink-500">Tidak ada kandidat IOC; hanya hash yang akan ditambahkan.</p></div>
      </div>
      <template #footer><CrButton variant="ghost" @click="promote = null">Batal</CrButton><CrButton variant="primary" data-test="do-promote" @click="doPromote">Promosikan</CrButton></template>
    </CrModal>
    <CrModal :open="!!sbx" title="Kirim ke sandbox terisolasi" width="max-w-xl" @close="sbx = null">
      <div v-if="sbx" class="space-y-3 text-sm">
        <p class="rounded border border-sev-high/40 bg-sev-high/5 p-2 text-xs text-ink-300">Sampel dikirim ke sandbox eksternal sekali pakai ({{ meta?.sandbox.provider }}) dengan routing jaringan dinonaktifkan. Sampel tidak pernah dijalankan di platform ini.</p>
        <div><label class="field-label" for="sb-just">Justifikasi</label><textarea id="sb-just" v-model="sbx.justification" class="input" rows="2" /></div>
        <div><label class="field-label" for="sb-to">Timeout (detik)</label><input id="sb-to" v-model="sbx.timeout_seconds" type="number" min="30" max="600" class="input w-32" /></div>
        <label class="flex items-center gap-2 text-xs"><input v-model="sbx.acknowledge_isolation" type="checkbox" class="accent-cyan-400" /> Saya mengonfirmasi sampel hanya berjalan di dalam sandbox terisolasi yang sekali pakai.</label>
      </div>
      <template #footer><CrButton variant="ghost" @click="sbx = null">Batal</CrButton><CrButton variant="primary" :disabled="!sbx?.acknowledge_isolation || (sbx?.justification || '').trim().length < 10" @click="doSandbox">Kirim</CrButton></template>
    </CrModal>
    <CrModal :open="!!toCase" title="Tambah sampel sebagai evidence" width="max-w-lg" @close="toCase = null">
      <div v-if="toCase" class="space-y-3 text-sm">
        <div v-if="!cases.length" class="text-xs text-ink-400">Tidak ada kasus terbuka. <RouterLink :to="{ name: 'cases' }" class="text-accent-300 hover:underline">Buka di Kasus & Evidence</RouterLink>.</div>
        <div v-else><label class="field-label" for="tc-case">Kasus</label><select id="tc-case" v-model="toCase.case_id" class="input"><option v-for="c in cases" :key="c.id" :value="c.id">{{ c.reference }} · {{ c.title }}</option></select></div>
        <div><label class="field-label" for="tc-title">Judul (opsional)</label><input id="tc-title" v-model="toCase.title" class="input" /></div>
      </div>
      <template #footer><CrButton variant="ghost" @click="toCase = null">Batal</CrButton><CrButton variant="primary" :disabled="!toCase?.case_id" @click="doToCase">Tambah</CrButton></template>
    </CrModal>
  </template>
</template>
