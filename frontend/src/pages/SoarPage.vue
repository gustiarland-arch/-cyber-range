<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Check, Plus, ShieldQuestion, Trash2, X } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const canRespond = computed(() => auth.can('incident.respond'))
const canManage = computed(() => auth.can('soar.manage'))
const tab = ref(route.query.tab === 'playbooks' ? 'playbooks' : 'runs')
watch(tab, (t) => router.replace({ query: { ...route.query, tab: t === 'playbooks' ? 'playbooks' : undefined } }))

const RUN_TONE = { running: 'info', awaiting_approval: 'warn', completed: 'ok', rejected: 'neutral', failed: 'bad', cancelled: 'neutral' }
const RUN_LABEL = { running: 'running', awaiting_approval: 'menunggu persetujuan', completed: 'selesai', rejected: 'ditolak', failed: 'gagal', cancelled: 'dibatalkan' }
const STEP_LABEL = { pending: 'belum', done: 'selesai', awaiting_approval: 'menunggu', failed: 'gagal', rejected: 'ditolak', skipped: 'dilewati' }
const STEP_TONE = { pending: 'neutral', done: 'ok', awaiting_approval: 'warn', failed: 'bad', rejected: 'neutral', skipped: 'neutral' }

const meta = ref(null)
const runs = ref(null)
const runFilter = ref('open')
const err = ref(null)
async function loadRuns() { try { runs.value = await api('/soar/runs', { query: { status: runFilter.value } }); err.value = null } catch (e) { err.value = e } }
watch(runFilter, loadRuns)
const playbooks = ref(null)
async function loadPlaybooks() { try { playbooks.value = (await api('/soar/playbooks')).items } catch (e) { ui.error(e) } }

const run = ref(null)
const note = ref('')
async function openRun(id) {
  try { run.value = await api(`/soar/runs/${id}`); note.value = ''; router.replace({ query: { ...route.query, run: id } }) } catch (e) { ui.error(e) }
}
function closeRun() { run.value = null; const { run: _r, ...q } = route.query; router.replace({ query: q }) }
const busy = ref(false)
async function decide(approve) {
  busy.value = true
  try {
    run.value = await api(`/soar/runs/${run.value.id}/decision`, { method: 'POST', body: { step: run.value.current_step, approve, note: note.value } })
    note.value = ''
    ui.success(approve ? 'Langkah disetujui dan dijalankan' : 'Langkah ditolak; run dihentikan')
    loadRuns()
  } catch (e) { ui.error(e) } finally { busy.value = false }
}
async function cancelRun() {
  try { run.value = await api(`/soar/runs/${run.value.id}/cancel`, { method: 'POST' }); ui.success('Run dibatalkan'); loadRuns() } catch (e) { ui.error(e) }
}

// ------------------------------------------------------------------ playbook editor
const editor = ref(null)
const actionLabel = (a) => meta.value?.actions.find((x) => x.action === a)?.label || a
const needsApproval = (a) => meta.value?.actions.find((x) => x.action === a)?.approval
function newPlaybook() {
  editor.value = { code: 'PB-', name: '', description: '', mode: 'manual', rule_codes: '', min_severity: 3, steps: [{ action: 'collect_iocs', params: {} }, { action: 'enrich', params: {} }] }
}
function addStep() { editor.value.steps.push({ action: 'add_note', params: { text: '' } }) }
function onAction(s) {
  s.params = s.action === 'add_note' ? { text: '' } : s.action === 'watchlist_ip' ? { fields: ['src_ip'], days: 7 } : s.action === 'close_alert' ? { status: 'false_positive', resolution: '' } : s.action === 'notify' ? { message: '' } : {}
}
function cleanParams(s) {
  const p = { ...s.params }
  if (s.action === 'notify' && !p.message) delete p.message
  if (s.action === 'close_alert' && !p.resolution) delete p.resolution
  return p
}
async function savePlaybook() {
  const e = editor.value
  const body = { code: e.code.trim().toUpperCase(), name: e.name, description: e.description,
    trigger: { mode: e.mode, rule_codes: e.rule_codes.split(',').map((x) => x.trim()).filter(Boolean), min_severity: Number(e.min_severity) },
    steps: e.steps.map((s) => ({ action: s.action, params: cleanParams(s) })) }
  try { await api('/soar/playbooks', { method: 'POST', body }); editor.value = null; ui.success('Playbook dibuat'); loadPlaybooks() } catch (err2) { ui.error(err2) }
}
async function toggle(pb) {
  try { await api(`/soar/playbooks/${pb.id}`, { method: 'PATCH', body: { is_enabled: !pb.is_enabled } }); loadPlaybooks() } catch (e) { ui.error(e) }
}
async function removePb(pb) {
  try { await api(`/soar/playbooks/${pb.id}`, { method: 'DELETE' }); ui.success('Playbook dihapus'); loadPlaybooks() } catch (e) { ui.error(e) }
}
const triggerText = (t) => (t.mode === 'auto' ? `otomatis · severity ≥ ${['info', 'low', 'medium', 'high', 'critical'][t.min_severity]}${t.rule_codes.length ? ' · rule ' + t.rule_codes.join(', ') : ' · semua rule'}` : 'manual')

onMounted(async () => {
  try { meta.value = await api('/soar/meta') } catch (e) { err.value = e }
  loadRuns(); loadPlaybooks()
  if (route.query.run) openRun(Number(route.query.run))
})
</script>

<template>
  <PageHeader section="Blue Team Operations" title="SOAR Playbook" subtitle="Otomasi respons ringan. Langkah pengumpulan dan pengayaan berjalan otomatis; setiap langkah yang mengubah sesuatu menunggu persetujuan manusia.">
    <CrButton v-if="canManage && tab === 'playbooks'" variant="primary" @click="newPlaybook"><Plus class="size-4" /> Playbook baru</CrButton>
  </PageHeader>
  <div class="mb-4 inline-flex overflow-hidden rounded-md border border-ink-600 text-sm" role="tablist">
    <button :class="['px-3 py-1.5', tab === 'runs' ? 'bg-accent-500/20 text-accent-200' : 'text-ink-300']" role="tab" @click="tab = 'runs'">
      Run <CrBadge v-if="runs?.awaiting_approval" tone="warn" class="ml-1" data-test="pending-count">{{ runs.awaiting_approval }}</CrBadge></button>
    <button :class="['px-3 py-1.5', tab === 'playbooks' ? 'bg-accent-500/20 text-accent-200' : 'text-ink-300']" role="tab" @click="tab = 'playbooks'">Playbook</button>
  </div>
  <CrState v-if="err" kind="error" :message="err.message" @retry="loadRuns" />

  <template v-else-if="tab === 'runs'">
    <div class="mb-3 flex items-center gap-2 text-sm">
      <select v-model="runFilter" class="input w-56" aria-label="Filter status">
        <option value="open">Terbuka (berjalan / menunggu)</option><option value="awaiting_approval">Menunggu persetujuan</option>
        <option value="completed">Selesai</option><option value="failed">Gagal</option><option value="rejected">Ditolak</option><option value="all">Semua</option>
      </select>
      <span class="text-xs text-ink-500">Jalankan playbook dari panel alert di <RouterLink :to="{ name: 'incident-response' }" class="text-accent-300 underline">Respons Insiden</RouterLink>.</span>
    </div>
    <CrState v-if="!runs" kind="loading" />
    <CrState v-else-if="!runs.items.length" kind="empty" title="Tidak ada run" message="Belum ada playbook yang dijalankan dengan filter ini." />
    <CrPanel v-else :padded="false">
      <table class="data-table" data-test="runs">
        <thead><tr><th>Run</th><th>Playbook</th><th>Alert</th><th>Status</th><th>Langkah</th><th>Pemicu</th><th>Dibuat</th></tr></thead>
        <tbody><tr v-for="r in runs.items" :key="r.id" class="cursor-pointer hover:bg-ink-800/60" @click="openRun(r.id)">
          <td class="font-mono">#{{ r.id }} <DemoTag v-if="r.is_demo" /></td>
          <td><span class="font-mono text-xs">{{ r.playbook.code }}</span> {{ r.playbook.name }}</td>
          <td><SevBadge :sev="r.alert.severity" /> <span class="text-xs">#{{ r.alert.id }} {{ r.alert.title }}</span></td>
          <td><CrBadge :tone="RUN_TONE[r.status]">{{ RUN_LABEL[r.status] }}</CrBadge><div v-if="r.waiting" class="mt-0.5 text-[11px] text-warn">{{ r.waiting.label }}</div></td>
          <td class="font-mono text-xs">{{ Math.min(r.current_step + (r.status === 'completed' ? 0 : 1), r.steps_total) }}/{{ r.steps_total }}</td>
          <td class="text-xs">{{ r.trigger === 'auto' ? 'otomatis' : r.requested_by }}</td><td class="text-xs">{{ ago(r.created_at) }}</td>
        </tr></tbody>
      </table>
    </CrPanel>
  </template>

  <template v-else>
    <CrState v-if="!playbooks" kind="loading" />
    <div v-else class="grid gap-3 lg:grid-cols-2">
      <CrPanel v-for="pb in playbooks" :key="pb.id" :title="pb.name" :data-pb="pb.code">
        <template #actions>
          <CrBadge v-if="pb.builtin">bawaan</CrBadge>
          <CrButton size="sm" :disabled="!canManage" :title="canManage ? '' : 'memerlukan: soar.manage'" @click="toggle(pb)">{{ pb.is_enabled ? 'Nonaktifkan' : 'Aktifkan' }}</CrButton>
          <CrButton v-if="!pb.builtin && canManage" size="sm" variant="ghost" :aria-label="`Hapus ${pb.code}`" @click="removePb(pb)"><Trash2 class="size-3.5" /></CrButton>
        </template>
        <p class="mb-2 text-xs text-ink-400"><span class="font-mono">{{ pb.code }}</span> · pemicu {{ triggerText(pb.trigger) }} · {{ pb.runs_total }} run ·
          <CrBadge :tone="pb.is_enabled ? 'ok' : 'neutral'">{{ pb.is_enabled ? 'aktif' : 'nonaktif' }}</CrBadge></p>
        <p class="mb-2 text-sm text-ink-300">{{ pb.description }}</p>
        <ol class="space-y-1 text-sm">
          <li v-for="(s, i) in pb.steps" :key="i" class="flex items-start gap-2">
            <span class="font-mono text-xs text-ink-500">{{ i + 1 }}.</span>
            <span>{{ s.label }}</span>
            <CrBadge v-if="s.approval" tone="warn" class="shrink-0"><ShieldQuestion class="mr-0.5 inline size-3" />perlu persetujuan</CrBadge>
          </li>
        </ol>
      </CrPanel>
    </div>
  </template>

  <CrModal :open="!!run" :title="run ? `Run #${run.id} · ${run.playbook.name}` : ''" width="max-w-3xl" @close="closeRun">
    <div v-if="run" class="space-y-4 text-sm">
      <div class="flex flex-wrap items-center gap-2">
        <CrBadge :tone="RUN_TONE[run.status]">{{ RUN_LABEL[run.status] }}</CrBadge><DemoTag v-if="run.is_demo" />
        <span>Alert <RouterLink :to="{ name: 'incident-response', query: { alert: run.alert.id } }" class="text-accent-300 underline">#{{ run.alert.id }} {{ run.alert.title }}</RouterLink></span>
        <RouterLink v-if="run.alert.incident_id" :to="{ name: 'incident-detail', params: { id: run.alert.incident_id } }" class="text-accent-300 underline">Insiden #{{ run.alert.incident_id }}</RouterLink>
        <span class="text-xs text-ink-500">dibuat {{ fmtTime(run.created_at) }} · {{ run.trigger === 'auto' ? 'pemicu otomatis' : 'oleh ' + run.requested_by }}</span>
      </div>
      <p v-if="run.error" class="rounded border border-sev-critical/40 bg-sev-critical/10 p-2 text-xs text-sev-critical">{{ run.error }}</p>
      <ol class="space-y-2" data-test="run-steps">
        <li v-for="(s, i) in run.steps" :key="i" :class="['rounded border p-2', s.status === 'awaiting_approval' ? 'border-warn/60 bg-warn/5' : 'border-ink-700']">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-xs text-ink-500">{{ i + 1 }}.</span><span class="font-medium text-ink-100">{{ s.label }}</span>
            <CrBadge :tone="STEP_TONE[s.status]">{{ STEP_LABEL[s.status] }}</CrBadge>
            <CrBadge v-if="s.approval" tone="warn">perlu persetujuan</CrBadge>
            <span v-if="s.by" class="text-[11px] text-ink-500">oleh {{ s.by }}</span>
          </div>
          <p v-if="s.decision" class="mt-1 text-xs text-ink-400">{{ s.decision.approved ? 'Disetujui' : 'Ditolak' }} oleh {{ s.decision.by }}<span v-if="s.decision.note">: "{{ s.decision.note }}"</span></p>
          <p v-if="s.error" class="mt-1 text-xs text-sev-critical">{{ s.error }}</p>
          <pre v-if="s.result" class="mt-1 max-h-40 overflow-auto rounded bg-ink-950 p-2 font-mono text-[11px] text-ink-300">{{ JSON.stringify(s.result, null, 2) }}</pre>
        </li>
      </ol>
      <section v-if="run.status === 'awaiting_approval'" class="rounded border border-warn/50 p-3" data-test="approval">
        <h3 class="mb-1 font-medium text-ink-100">Persetujuan langkah {{ run.current_step + 1 }}: {{ run.waiting.label }}</h3>
        <p class="mb-2 text-xs text-ink-400">Periksa bukti di atas (observable, kecocokan intel, lab terkait) sebelum menyetujui. Keputusan dicatat di audit log.</p>
        <textarea v-model="note" class="input mb-2 h-16 w-full" maxlength="2000" placeholder="Catatan (wajib bila menolak)" aria-label="Catatan keputusan" />
        <div class="flex flex-wrap gap-2">
          <CrButton variant="primary" :disabled="!canRespond" :loading="busy" :title="canRespond ? '' : 'memerlukan: incident.respond'" data-test="approve" @click="decide(true)"><Check class="size-4" /> Setujui &amp; jalankan</CrButton>
          <CrButton variant="danger" :disabled="!canRespond || !note.trim()" :title="note.trim() ? '' : 'Isi alasan penolakan'" data-test="reject" @click="decide(false)"><X class="size-4" /> Tolak</CrButton>
          <CrButton :disabled="!canRespond" @click="cancelRun">Batalkan run</CrButton>
        </div>
      </section>
    </div>
  </CrModal>

  <CrModal :open="!!editor" title="Playbook baru" width="max-w-3xl" @close="editor = null">
    <div v-if="editor" class="space-y-3 text-sm">
      <div class="grid gap-3 md:grid-cols-2">
        <label><span class="field-label">Kode</span><input v-model="editor.code" class="input w-full font-mono" maxlength="40" /></label>
        <label><span class="field-label">Nama</span><input v-model="editor.name" class="input w-full" maxlength="160" /></label>
      </div>
      <label class="block"><span class="field-label">Deskripsi</span><textarea v-model="editor.description" class="input h-16 w-full" maxlength="4000" /></label>
      <div class="grid gap-3 md:grid-cols-3">
        <label><span class="field-label">Pemicu</span><select v-model="editor.mode" class="input w-full"><option value="manual">Manual</option><option value="auto">Otomatis saat alert baru</option></select></label>
        <label v-if="editor.mode === 'auto'"><span class="field-label">Severity minimum</span><select v-model.number="editor.min_severity" class="input w-full"><option v-for="(n, i) in ['info', 'low', 'medium', 'high', 'critical']" :key="i" :value="i">{{ n }}</option></select></label>
        <label v-if="editor.mode === 'auto'"><span class="field-label">Kode rule (kosong = semua)</span><input v-model="editor.rule_codes" class="input w-full font-mono" placeholder="CR-TI-001, CR-NET-002" /></label>
      </div>
      <p v-if="editor.mode === 'auto'" class="text-xs text-ink-500">Pemicu otomatis hanya menjalankan langkah tanpa persetujuan, lalu berhenti dan menunggu analis.</p>
      <section>
        <h3 class="field-label">Langkah (maks. {{ meta?.max_steps }})</h3>
        <div v-for="(s, i) in editor.steps" :key="i" class="mb-2 rounded border border-ink-700 p-2">
          <div class="flex items-center gap-2">
            <span class="font-mono text-xs text-ink-500">{{ i + 1 }}.</span>
            <select v-model="s.action" class="input flex-1" :aria-label="`Aksi langkah ${i + 1}`" @change="onAction(s)">
              <option v-for="a in meta?.actions" :key="a.action" :value="a.action">{{ a.label }}{{ a.approval ? ' (perlu persetujuan)' : '' }}</option>
            </select>
            <CrButton size="sm" variant="ghost" :aria-label="`Hapus langkah ${i + 1}`" :disabled="editor.steps.length < 2" @click="editor.steps.splice(i, 1)"><Trash2 class="size-3.5" /></CrButton>
          </div>
          <input v-if="s.action === 'add_note'" v-model="s.params.text" class="input mt-2 w-full" maxlength="2000" placeholder="Isi catatan" />
          <input v-if="s.action === 'notify'" v-model="s.params.message" class="input mt-2 w-full" maxlength="1000" placeholder="Pesan tambahan (opsional)" />
          <div v-if="s.action === 'watchlist_ip'" class="mt-2 flex flex-wrap items-center gap-3 text-xs">
            <label class="flex items-center gap-1"><input v-model="s.params.fields" type="checkbox" value="src_ip" /> IP sumber</label>
            <label class="flex items-center gap-1"><input v-model="s.params.fields" type="checkbox" value="dst_ip" /> IP tujuan</label>
            <label class="flex items-center gap-1">berlaku <input v-model.number="s.params.days" type="number" min="1" max="90" class="input w-20" /> hari</label>
          </div>
          <div v-if="s.action === 'close_alert'" class="mt-2 flex flex-wrap gap-2">
            <select v-model="s.params.status" class="input w-48"><option value="false_positive">false positive</option><option value="resolved">resolved</option></select>
            <input v-model="s.params.resolution" class="input flex-1" maxlength="2000" placeholder="Catatan resolusi (opsional)" />
          </div>
          <p v-if="needsApproval(s.action)" class="mt-1 text-[11px] text-warn">Langkah ini menunggu persetujuan manusia saat dijalankan.</p>
        </div>
        <CrButton size="sm" :disabled="editor.steps.length >= (meta?.max_steps || 12)" @click="addStep"><Plus class="size-3.5" /> Tambah langkah</CrButton>
      </section>
      <p class="text-xs text-ink-500">Tersedia: {{ meta?.actions.map((a) => actionLabel(a.action)).length }} aksi dari katalog aman. Tidak ada langkah skrip, shell atau HTTP bebas.</p>
    </div>
    <template #footer><CrButton @click="editor = null">Batal</CrButton>
      <CrButton variant="primary" :disabled="!editor || editor.name.trim().length < 3 || editor.code.trim().length < 3" @click="savePlaybook">Simpan</CrButton></template>
  </CrModal>
</template>
