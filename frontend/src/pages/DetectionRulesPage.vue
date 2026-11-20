<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { FileCode2, FileUp, FlaskConical, Pencil, Plus, Trash2, X } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago } from '@/services/format'
import { SEVERITIES } from '@/services/soc'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import EventTable from '@/components/soc/EventTable.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const auth = useAuthStore()
const ui = useUiStore()
const rules = ref(null)
const meta = ref(null)
const err = ref(null)
const canManage = computed(() => auth.can('blueteam.rules.manage'))
async function load() { try { [rules.value, meta.value] = await Promise.all([api('/soc/rules'), api('/soc/rules/meta')]); err.value = null } catch (e) { err.value = e } }
onMounted(load)

const GROUP_OPS = ['any_of', 'none_of']
const isGroup = (c) => GROUP_OPS.includes(c.op)
const fmtList = (cs) => cs.map(fmtCond).join(' DAN ')
function fmtCond(c) {
  if (c.op === 'any_of') return c.value.map((g) => `(${fmtList(g)})`).join(' ATAU ')
  if (c.op === 'none_of') return `BUKAN ${c.value.map((g) => `(${fmtList(g)})`).join(' ATAU ')}`
  return `${c.field} ${c.op} ${Array.isArray(c.value) ? `[${c.value.join(', ')}]` : c.value}`
}
const ORIGIN = { builtin: 'bawaan', sigma: 'Sigma', manual: 'manual' }

// Sigma import
const sig = ref(null)
const sigPreview = ref(null)
const sigBusy = ref(false)
function openSigma() { sig.value = { source: '', enable: false, overwrite: false }; sigPreview.value = null }
async function sigFile(ev) {
  const f = ev.target.files?.[0]
  if (!f) return
  if (f.size > 200000) return ui.error({ message: 'File Sigma maksimal 200 KB' })
  sig.value.source = await f.text(); sigPreview.value = null
}
async function previewSigma() {
  sigBusy.value = true
  try { sigPreview.value = (await api('/soc/rules/sigma/preview', { method: 'POST', body: sig.value })).results } catch (e) { ui.error(e) } finally { sigBusy.value = false }
}
async function importSigma() {
  sigBusy.value = true
  try {
    const r = await api('/soc/rules/sigma/import', { method: 'POST', body: sig.value })
    ui.success(`Sigma: ${r.created.length} dibuat, ${r.updated.length} diperbarui, ${r.skipped.length} dilewati, ${r.errors.length} gagal`)
    sig.value = null; load()
  } catch (e) { ui.error(e) } finally { sigBusy.value = false }
}
const sigOk = computed(() => (sigPreview.value || []).filter((x) => x.ok).length)
const srcView = ref(null)
async function viewSource(r) { try { srcView.value = await api(`/soc/rules/${r.id}/source`) } catch (e) { ui.error(e) } }
async function toggle(r) { try { await api(`/soc/rules/${r.id}`, { method: 'PATCH', body: { is_enabled: !r.is_enabled } }); load() } catch (e) { ui.error(e) } }

const blank = () => ({ id: null, code: '', name: '', description: '', severity: 2, kind: 'match', group_by: '', mitre_tactic: '', mitre_technique: '', is_enabled: true,
  conditions: [{ field: 'category', op: 'eq', value: '' }], threshold: { count: 5, window_seconds: 60, group_by: 'src_ip', distinct: '' } })
const edit = ref(null)
const errors = ref([])
const test = ref(null)
function open(r) {
  errors.value = []; test.value = null
  const advanced = !!r && r.conditions.some(isGroup)
  edit.value = r ? { ...JSON.parse(JSON.stringify(r)), group_by: r.group_by || '', mitre_tactic: r.mitre_tactic || '', mitre_technique: r.mitre_technique || '',
    threshold: r.threshold ? { distinct: '', ...r.threshold } : blank().threshold, advanced, condJson: advanced ? JSON.stringify(r.conditions, null, 2) : '',
    conditions: advanced ? [] : r.conditions.map((c) => ({ ...c, value: Array.isArray(c.value) ? c.value.join(', ') : String(c.value) })) } : blank()
}
function coerce(c) {
  if (c.op === 'in' || c.op === 'not_in') return { ...c, value: c.value.split(',').map((x) => x.trim()).filter(Boolean) }
  if (c.op === 'gte' || c.op === 'lte') return { ...c, value: Number(c.value) }
  if (c.op === 'exists') return { ...c, value: c.value !== 'false' }
  return c
}
function payload() {
  const e = edit.value
  const t = e.kind === 'threshold' ? { count: Number(e.threshold.count), window_seconds: Number(e.threshold.window_seconds), group_by: e.threshold.group_by, ...(e.threshold.distinct ? { distinct: e.threshold.distinct } : {}) } : null
  let conditions
  if (e.advanced) {
    try { conditions = JSON.parse(e.condJson) } catch { throw new Error('Kondisi JSON tidak valid') }
  } else conditions = e.conditions.map(coerce)
  return { code: e.code, name: e.name, description: e.description, severity: Number(e.severity), kind: e.kind, conditions, threshold: t,
    group_by: e.kind === 'match' && e.group_by ? e.group_by : null, mitre_tactic: e.mitre_tactic || null, mitre_technique: e.mitre_technique || null, is_enabled: e.is_enabled }
}
const showErr = (e) => { if (!e.details) { errors.value = [e.message]; return } errors.value = Array.isArray(e.details) ? e.details.map((d) => (typeof d === 'string' ? d : `${(d.loc || []).slice(1).join('.')}: ${d.msg}`)) : [e.message] }
async function save() {
  errors.value = []
  try {
    payload()
  } catch (e) { return showErr(e) }
  try {
    await api(edit.value.id ? `/soc/rules/${edit.value.id}` : '/soc/rules', { method: edit.value.id ? 'PUT' : 'POST', body: payload() })
    ui.success('Rule disimpan'); edit.value = null; load()
  } catch (e) { showErr(e) }
}
async function backtest() {
  errors.value = []; test.value = null
  let p
  try { p = payload() } catch (e) { return showErr(e) }
  try { test.value = await api('/soc/rules/test', { method: 'POST', body: { kind: p.kind, conditions: p.conditions, threshold: p.threshold, group_by: p.group_by, hours: 24 } }) } catch (e) { showErr(e) }
}
const delTarget = ref(null)
async function del() { try { await api(`/soc/rules/${delTarget.value.id}`, { method: 'DELETE' }); ui.success('Rule dihapus'); delTarget.value = null; load() } catch (e) { ui.error(e); delTarget.value = null } }
const editorTitle = computed(() => (edit.value?.id ? `Edit ${edit.value.code}` : 'Rule deteksi baru'))
</script>

<template>
  <PageHeader section="Blue Team Operations" title="Rule Deteksi" subtitle="Rule dijalankan pada setiap event yang masuk. Rule threshold menghitung event yang cocok per grup dalam jendela geser.">
    <RouterLink :to="{ name: 'attack-coverage' }" class="inline-flex h-9 items-center gap-1.5 rounded-md border border-ink-600 bg-ink-800 px-3 text-sm text-ink-100 hover:bg-ink-700">Matriks ATT&amp;CK</RouterLink>
    <CrButton v-if="canManage" data-test="sigma-open" @click="openSigma"><FileUp class="size-4" /> Impor Sigma</CrButton>
    <CrButton v-if="canManage" variant="primary" @click="open(null)"><Plus class="size-4" /> Rule baru</CrButton>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!rules" kind="loading" />
  <div v-else class="panel">
    <table class="data-table">
      <thead><tr><th>Rule</th><th>Logika</th><th>Severity</th><th>MITRE ATT&amp;CK</th><th>Hits</th><th>Status</th><th v-if="canManage" /></tr></thead>
      <tbody>
        <tr v-for="r in rules" :key="r.id" :data-rule="r.code">
          <td><div class="font-mono text-[11px] text-ink-500">{{ r.code }} · v{{ r.version }} · {{ ORIGIN[r.origin] || r.origin }}<button v-if="r.origin === 'sigma'" class="ml-1 text-accent-300 hover:underline" @click="viewSource(r)">sumber</button></div><div class="text-ink-100">{{ r.name }}</div><div class="max-w-md text-xs text-ink-500">{{ r.description }}</div></td>
          <td class="max-w-sm font-mono text-[11px] text-ink-300">
            <div v-for="(c, i) in r.conditions" :key="i">{{ fmtCond(c) }}</div>
            <div v-if="r.kind === 'threshold'" class="text-accent-300">≥ {{ r.threshold.count }} {{ r.threshold.distinct ? `distinct ${r.threshold.distinct}` : 'events' }} / {{ r.threshold.window_seconds }} dtk oleh {{ r.threshold.group_by }}</div>
            <div v-else-if="r.kind === 'intel'" class="text-ai-300">indikator threat-intel aktif di event · <RouterLink :to="{ name: 'threat-intel' }" class="underline">kelola indikator</RouterLink></div>
            <div v-else-if="r.group_by" class="text-ink-500">dikelompokkan berdasarkan {{ r.group_by }}</div>
          </td>
          <td><SevBadge :sev="r.severity" /></td>
          <td class="text-xs"><div>{{ r.mitre_tactic || '—' }}</div><div class="font-mono text-[11px] text-ink-500">{{ r.mitre_technique }}<span v-if="r.mitre_name" class="font-sans"> {{ r.mitre_name }}</span></div></td>
          <td class="font-mono text-xs">{{ r.hits }}<div v-if="r.last_hit_at" class="text-[10px] text-ink-500">{{ ago(r.last_hit_at) }}</div></td>
          <td><CrBadge :tone="r.is_enabled ? 'ok' : 'neutral'">{{ r.is_enabled ? 'aktif' : 'nonaktif' }}</CrBadge></td>
          <td v-if="canManage" class="whitespace-nowrap text-right">
            <CrButton size="sm" variant="ghost" @click="toggle(r)">{{ r.is_enabled ? 'Nonaktifkan' : 'Aktifkan' }}</CrButton>
            <CrButton v-if="r.kind !== 'intel'" size="sm" variant="ghost" title="Ubah" @click="open(r)"><Pencil class="size-3.5" /></CrButton>
            <CrButton v-if="!r.is_builtin" size="sm" variant="ghost" title="Hapus" @click="delTarget = r"><Trash2 class="size-3.5" /></CrButton>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <CrModal :open="!!edit" :title="editorTitle" width="max-w-3xl" @close="edit = null">
    <div v-if="edit && meta" class="space-y-3">
      <div class="grid grid-cols-3 gap-3">
        <div><label class="field-label" for="r-code">Kode</label><input id="r-code" v-model="edit.code" class="input font-mono" :disabled="!!edit.id" placeholder="CUSTOM-NET-1" /></div>
        <div class="col-span-2"><label class="field-label" for="r-name">Nama</label><input id="r-name" v-model="edit.name" class="input" /></div>
      </div>
      <div><label class="field-label" for="r-desc">Deskripsi</label><textarea id="r-desc" v-model="edit.description" class="input" rows="2" /></div>
      <div class="grid grid-cols-4 gap-3">
        <div><label class="field-label" for="r-sev">Severity</label><select id="r-sev" v-model.number="edit.severity" class="input"><option v-for="(s, i) in SEVERITIES" :key="s" :value="i">{{ s }}</option></select></div>
        <div><label class="field-label" for="r-kind">Tipe</label><select id="r-kind" v-model="edit.kind" class="input"><option value="match">match</option><option value="threshold">threshold</option></select></div>
        <div><label class="field-label" for="r-tac">Taktik MITRE</label><select id="r-tac" v-model="edit.mitre_tactic" class="input"><option value="">—</option><option v-for="t in meta.tactics" :key="t" :value="t">{{ t }}</option></select></div>
        <div><label class="field-label" for="r-tech">Teknik</label><input id="r-tech" v-model="edit.mitre_technique" class="input font-mono" placeholder="T1110" list="attack-techs" />
          <datalist id="attack-techs"><option v-for="t in meta.techniques" :key="t.id" :value="t.id">{{ t.name }}</option></datalist></div>
      </div>
      <div v-if="edit.advanced">
        <label class="field-label" for="r-json">Kondisi lanjutan (JSON: daftar kondisi, mendukung any_of / none_of)</label>
        <textarea id="r-json" v-model="edit.condJson" class="input font-mono text-xs" rows="10" spellcheck="false" />
      </div>
      <div v-else>
        <div class="field-label">Kondisi (semua harus cocok)</div>
        <div v-for="(c, i) in edit.conditions" :key="i" class="mb-1.5 flex gap-2" :data-cond="i">
          <select v-model="c.field" class="input w-36" aria-label="Field"><option v-for="f in meta.fields" :key="f">{{ f }}</option></select>
          <select v-model="c.op" class="input w-28" aria-label="Operator"><option v-for="o in meta.ops" :key="o">{{ o }}</option></select>
          <input v-model="c.value" class="input flex-1 font-mono" aria-label="Nilai" :placeholder="c.op === 'in' ? 'a, b, c' : c.op === 'cidr' ? '10.0.0.0/8' : ''" />
          <CrButton size="sm" variant="ghost" :disabled="edit.conditions.length < 2" aria-label="Hapus kondisi" @click="edit.conditions.splice(i, 1)"><X class="size-3.5" /></CrButton>
        </div>
        <CrButton size="sm" variant="ghost" @click="edit.conditions.push({ field: 'message', op: 'contains', value: '' })"><Plus class="size-3.5" /> Kondisi</CrButton>
      </div>
      <div v-if="edit.kind === 'threshold'" class="grid grid-cols-4 gap-3 rounded border border-ink-700 p-3">
        <div><label class="field-label" for="t-count">Minimal</label><input id="t-count" v-model.number="edit.threshold.count" type="number" min="2" class="input" /></div>
        <div><label class="field-label" for="t-distinct">Hitung unik</label><select id="t-distinct" v-model="edit.threshold.distinct" class="input"><option value="">event</option><option v-for="f in meta.fields" :key="f" :value="f">{{ f }}</option></select></div>
        <div><label class="field-label" for="t-win">Dalam (detik)</label><input id="t-win" v-model.number="edit.threshold.window_seconds" type="number" min="10" class="input" /></div>
        <div><label class="field-label" for="t-group">Per</label><select id="t-group" v-model="edit.threshold.group_by" class="input"><option v-for="f in meta.group_fields" :key="f">{{ f }}</option></select></div>
      </div>
      <div v-else><label class="field-label" for="r-group">Kelompokkan alert berdasarkan (opsional)</label><select id="r-group" v-model="edit.group_by" class="input w-48"><option value="">satu alert per rule</option><option v-for="f in meta.group_fields" :key="f">{{ f }}</option></select></div>
      <ul v-if="errors.length" class="rounded border border-sev-critical/40 bg-sev-critical/5 p-2 text-xs text-sev-critical" role="alert"><li v-for="(e, i) in errors" :key="i">{{ e }}</li></ul>
      <div v-if="test" class="rounded border border-ink-700 p-2" data-test="backtest">
        <div class="mb-2 font-mono text-xs">24 jam terakhir: dipindai {{ test.scanned }} · cocok {{ test.matched_events }} · akan memunculkan {{ test.would_alert }} alert
          <span v-if="test.would_alert_groups" class="text-ink-500"> {{ Object.entries(test.would_alert_groups).slice(0, 5).map(([g, n]) => `${g} (${n})`).join(', ') }}</span></div>
        <EventTable v-if="test.sample.length" :items="test.sample" compact />
      </div>
    </div>
    <template #footer>
      <CrButton class="mr-auto" @click="backtest"><FlaskConical class="size-4" /> Uji pada 24 jam terakhir</CrButton>
      <CrButton @click="edit = null">Batal</CrButton><CrButton variant="primary" @click="save">Simpan rule</CrButton>
    </template>
  </CrModal>
  <CrModal :open="!!sig" title="Impor rule Sigma" width="max-w-4xl" @close="sig = null">
    <div v-if="sig" class="space-y-3">
      <p class="text-xs text-ink-400">Tempel satu atau beberapa rule Sigma (YAML, dipisah <code>---</code>) atau pilih file .yml. Rule dikonversi ke model event ternormalisasi.
        Field atau fitur yang tidak punya padanan dilaporkan sebagai error, tidak diabaikan diam-diam. Rule hasil impor nonaktif secara default supaya bisa diuji dulu.</p>
      <div class="flex items-center gap-2"><label class="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md border border-ink-600 bg-ink-800 px-2.5 text-xs hover:bg-ink-700"><FileCode2 class="size-3.5" /> Pilih file<input type="file" accept=".yml,.yaml,.txt" class="hidden" @change="sigFile" /></label>
        <span class="text-xs text-ink-500">{{ sig.source.length }} karakter</span></div>
      <textarea v-model="sig.source" class="input font-mono text-xs" rows="12" spellcheck="false" aria-label="Sumber Sigma" placeholder="title: ...&#10;logsource:&#10;  category: webserver&#10;detection:&#10;  ..." data-test="sigma-source" @input="sigPreview = null" />
      <div class="flex flex-wrap gap-4 text-sm"><label class="flex items-center gap-2"><input v-model="sig.enable" type="checkbox" /> Langsung aktifkan</label>
        <label class="flex items-center gap-2"><input v-model="sig.overwrite" type="checkbox" /> Timpa rule Sigma dengan kode sama</label></div>
      <table v-if="sigPreview" class="data-table" data-test="sigma-preview">
        <thead><tr><th>Rule</th><th>Hasil</th><th>Logika</th><th>MITRE</th></tr></thead>
        <tbody><tr v-for="x in sigPreview" :key="x.index">
          <td><div class="text-ink-100">{{ x.title }}</div><div v-if="x.ok" class="font-mono text-[11px] text-ink-500">{{ x.rule.code }} · {{ x.rule.kind }}<span v-if="x.exists" class="text-warn"> · kode sudah ada</span></div></td>
          <td><CrBadge :tone="x.ok ? 'ok' : 'bad'">{{ x.ok ? 'siap' : 'gagal' }}</CrBadge><div v-if="!x.ok" class="mt-1 max-w-xs text-xs text-sev-critical">{{ x.error }}</div>
            <div v-for="(w, i) in x.warnings" :key="i" class="mt-1 max-w-xs text-xs text-warn">{{ w }}</div></td>
          <td class="max-w-md font-mono text-[11px] text-ink-300"><template v-if="x.ok"><div v-for="(c, i) in x.rule.conditions" :key="i">{{ fmtCond(c) }}</div>
            <div v-if="x.rule.threshold" class="text-accent-300">≥ {{ x.rule.threshold.count }} {{ x.rule.threshold.distinct ? `unik ${x.rule.threshold.distinct}` : 'event' }} / {{ x.rule.threshold.window_seconds }} dtk per {{ x.rule.threshold.group_by }}</div></template></td>
          <td class="text-xs"><template v-if="x.ok">{{ x.rule.mitre_tactic || '—' }}<div class="font-mono text-[11px] text-ink-500">{{ x.rule.mitre_technique }} {{ x.rule.mitre_name }}</div></template></td>
        </tr></tbody>
      </table>
    </div>
    <template #footer>
      <CrButton class="mr-auto" :loading="sigBusy" :disabled="(sig?.source || '').trim().length < 10" @click="previewSigma">Pratinjau konversi</CrButton>
      <CrButton @click="sig = null">Batal</CrButton>
      <CrButton variant="primary" :loading="sigBusy" :disabled="!sigOk" :title="sigOk ? '' : 'Jalankan pratinjau dulu; hanya rule yang siap yang diimpor'" data-test="sigma-import" @click="importSigma">Impor {{ sigOk || '' }} rule</CrButton>
    </template>
  </CrModal>
  <CrModal :open="!!srcView" :title="srcView ? `Sumber Sigma ${srcView.code}` : ''" width="max-w-3xl" @close="srcView = null">
    <pre class="max-h-[60vh] overflow-auto rounded bg-ink-950 p-3 font-mono text-xs text-ink-200">{{ srcView?.source_text }}</pre>
  </CrModal>
  <CrModal :open="!!delTarget" title="Hapus rule" @close="delTarget = null">
    <p class="text-sm">Hapus <b class="text-ink-100">{{ delTarget?.code }}</b>? Rule yang sudah memunculkan alert harus dinonaktifkan, bukan dihapus.</p>
    <template #footer><CrButton @click="delTarget = null">Batal</CrButton><CrButton variant="danger" @click="del">Hapus</CrButton></template>
  </CrModal>
</template>
