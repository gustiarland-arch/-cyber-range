<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { Download, FileBarChart, FilePlus2, Trash2 } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { ago } from '@/services/format'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPagination from '@/components/ui/CrPagination.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import { fmtBytes } from '@/components/malware/mw'

const ui = useUiStore()
const meta = ref(null)
const data = ref(null)
const err = ref(null)
const page = ref(1)
const filter = ref('')
const STATUS_TONE = { queued: 'neutral', running: 'accent', completed: 'ok', failed: 'bad' }
async function load() {
  try { data.value = await api('/reports', { query: { kind: filter.value, page: page.value } }); err.value = null } catch (e) { err.value = e }
}
watch([filter, page], load)

// builder
const form = ref({ kind: '', format: 'pdf', ref: '', status: 'open_all', days: 30 })
const options = ref([])
const loadingOpts = ref(false)
const kindInfo = computed(() => meta.value?.kinds.find((k) => k.kind === form.value.kind))
const SOURCES = {
  incident: ['/soc/incidents', { status: 'all' }, (r) => r.map((x) => ({ id: x.id, label: `#${x.id} ${x.title}` }))],
  assessment: ['/redteam/assessments', {}, (r) => r.map((x) => ({ id: x.id, label: `#${x.id} ${x.title} (${x.status})` }))],
  lab_run: ['/labs', {}, (r) => r.labs.map((x) => ({ id: x.id, label: `#${x.id} ${x.name}` }))],
  evidence: ['/forensics/cases', { status: 'all' }, (r) => r.map((x) => ({ id: x.id, label: `${x.reference} ${x.title}` }))],
}
watch(() => form.value.kind, async (k) => {
  form.value.ref = ''; options.value = []
  const src = SOURCES[k]
  if (!src || !kindInfo.value?.allowed) return
  loadingOpts.value = true
  try { options.value = src[2](await api(src[0], { query: src[1] })) } catch (e) { ui.error(e) } finally { loadingOpts.value = false }
})
const ready = computed(() => kindInfo.value?.allowed && (!kindInfo.value.param || form.value.ref))
const busy = ref(false)
async function generate() {
  busy.value = true
  const f = form.value
  const params = {}
  if (kindInfo.value.param) params[kindInfo.value.param] = Number(f.ref)
  if (f.kind === 'vulnerability') params.status = f.status
  if (f.kind === 'training') params.days = Number(f.days)
  try {
    const r = await api('/reports', { method: 'POST', body: { kind: f.kind, format: f.format, params } })
    ui.success(r.status === 'completed' ? 'Laporan dibuat' : 'Laporan masuk antrean')
    page.value = 1; load(); poll(r.id)
  } catch (e) { ui.error(e) } finally { busy.value = false }
}
async function poll(id, n = 0) {
  if (n > 30) return
  const r = await api(`/reports/${id}`).catch(() => null)
  if (r && ['queued', 'running'].includes(r.status)) setTimeout(() => poll(id, n + 1), 1500)
  else load()
}
async function dl(r) { try { await download(`/reports/${r.id}/download`, null, `cyber-range-${r.kind}-${r.id}.${r.format}`) } catch (e) { ui.error(e) } }
const toDelete = ref(null)
async function del() { try { await api(`/reports/${toDelete.value.id}`, { method: 'DELETE' }); toDelete.value = null; load() } catch (e) { ui.error(e) } }
onMounted(async () => { try { meta.value = await api('/reports/meta') } catch (e) { err.value = e } load() })
</script>

<template>
  <PageHeader section="Manajemen" title="Laporan" subtitle="Laporan insiden, assessment, lab run, kerentanan, evidence dan pelatihan dalam PDF atau CSV, disusun hanya dari data yang tersimpan." />
  <p v-if="meta" class="mb-4 rounded border border-ink-700 bg-ink-900/60 p-2 text-xs text-ink-400">{{ meta.policy }}
    <span v-if="!meta.pdf_unicode" class="ml-1 text-warn" data-test="pdf-latin1">Font PDF dengan Unicode lengkap tidak terpasang di server ini; karakter non-Latin di PDF tampil sebagai "?" (CSV tidak terpengaruh).</span></p>
  <div class="grid gap-4 lg:grid-cols-3">
    <CrPanel v-if="meta?.can_generate" title="Laporan baru">
      <form class="space-y-3" data-test="report-form" @submit.prevent="generate">
        <label class="block text-xs text-ink-400">Tipe laporan
          <select v-model="form.kind" class="input mt-1 w-full" data-field="kind" required>
            <option value="" disabled>pilih…</option>
            <option v-for="k in meta.kinds" :key="k.kind" :value="k.kind" :disabled="!k.allowed">{{ k.label }}{{ k.allowed ? '' : ` (needs ${k.perm})` }}</option>
          </select></label>
        <label v-if="kindInfo?.param" class="block text-xs text-ink-400">Subjek
          <select v-model="form.ref" class="input mt-1 w-full" data-field="ref" :disabled="loadingOpts" required>
            <option value="" disabled>{{ loadingOpts ? 'loading…' : options.length ? 'pilih…' : 'nothing available' }}</option>
            <option v-for="o in options" :key="o.id" :value="o.id">{{ o.label }}</option>
          </select></label>
        <label v-if="form.kind === 'vulnerability'" class="block text-xs text-ink-400">Temuan
          <select v-model="form.status" class="input mt-1 w-full"><option value="open_all">terbuka (termasuk remediasi)</option><option value="resolved">resolved</option><option value="any">semua</option></select></label>
        <label v-if="form.kind === 'training'" class="block text-xs text-ink-400">Periode
          <select v-model="form.days" class="input mt-1 w-full"><option :value="7">7 hari</option><option :value="30">30 hari</option><option :value="90">90 hari</option><option :value="365">365 hari</option></select></label>
        <fieldset class="flex gap-3 text-sm text-ink-300"><legend class="mb-1 text-xs text-ink-400">Format</legend>
          <label class="flex items-center gap-1"><input v-model="form.format" type="radio" value="pdf" class="accent-cyan-400" /> PDF</label>
          <label class="flex items-center gap-1"><input v-model="form.format" type="radio" value="csv" class="accent-cyan-400" /> CSV</label></fieldset>
        <CrButton type="submit" variant="primary" :loading="busy" :disabled="!ready" data-test="generate-report"><FilePlus2 class="size-4" /> Buat</CrButton>
      </form>
    </CrPanel>
    <CrPanel :title="meta?.can_manage ? 'Semua laporan' : 'Laporan saya'" :padded="false" :class="meta?.can_generate ? 'lg:col-span-2' : 'lg:col-span-3'">
      <template #actions>
        <select v-model="filter" class="input w-40" aria-label="Filter berdasarkan tipe"><option value="">semua tipe</option><option v-for="k in meta?.kinds || []" :key="k.kind" :value="k.kind">{{ k.label }}</option></select>
      </template>
      <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
      <CrState v-else-if="!data" kind="loading" />
      <CrState v-else-if="!data.items.length" kind="empty" title="Belum ada laporan" message="Laporan yang dibuat akan muncul di sini." />
      <table v-else class="w-full text-sm" data-test="reports">
        <thead class="text-left text-xs text-ink-500"><tr><th class="px-3 py-2">Laporan</th><th>Status</th><th>Oleh</th><th>Dibuat</th><th class="text-right">Ukuran</th><th class="px-3 text-right">Aksi</th></tr></thead>
        <tbody class="divide-y divide-ink-800">
          <tr v-for="r in data.items" :key="r.id" :data-report="r.id">
            <td class="px-3 py-2"><div class="flex items-center gap-2 text-ink-100"><FileBarChart class="size-4 text-accent-300" />{{ r.title }} <CrBadge>{{ r.format.toUpperCase() }}</CrBadge></div>
              <div class="mt-0.5 text-[11px] text-ink-500" :title="r.sources.join('\n')">sources: {{ r.sources.join('; ') }}</div>
              <div v-if="r.sha256" class="font-mono text-[10px] text-ink-600">sha256 {{ r.sha256.slice(0, 24) }}…</div>
              <div v-if="r.error" class="text-xs text-bad">{{ r.error }}</div></td>
            <td><CrBadge :tone="STATUS_TONE[r.status]" :data-status="r.status">{{ $st(r.status) }}</CrBadge></td>
            <td class="text-xs">{{ r.created_by }}</td><td class="text-xs text-ink-400">{{ ago(r.created_at) }}</td>
            <td class="text-right font-mono text-xs">{{ r.size ? fmtBytes(r.size) : '' }}</td>
            <td class="px-3 text-right whitespace-nowrap">
              <CrButton size="sm" :disabled="r.status !== 'completed'" :data-download="r.id" @click="dl(r)"><Download class="size-3.5" /> Unduh</CrButton>
              <CrButton v-if="meta?.can_generate" size="sm" variant="ghost" :aria-label="`Delete report ${r.id}`" @click="toDelete = r"><Trash2 class="size-3.5" /></CrButton>
            </td>
          </tr>
        </tbody>
      </table>
      <CrPagination v-if="data && data.total > 25" v-model:page="page" :total="data.total" :page-size="25" class="p-3" />
    </CrPanel>
  </div>
  <CrModal :open="!!toDelete" title="Hapus laporan?" @close="toDelete = null">
    <p class="text-sm text-ink-300">File yang dibuat untuk <b>{{ toDelete?.title }}</b> akan dihapus. Audit log tetap menyimpan catatan bahwa file ini pernah dibuat dan diunduh.</p>
    <template #footer><CrButton @click="toDelete = null">Batal</CrButton><CrButton variant="danger" @click="del">Hapus</CrButton></template>
  </CrModal>
</template>
