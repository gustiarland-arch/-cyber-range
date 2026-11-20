<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowUpRight, Plus, Search, UserCheck, Workflow } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { ALERT_STATUS_TONE, INCIDENT_TONE, SEVERITIES } from '@/services/soc'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPagination from '@/components/ui/CrPagination.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import EventModal from '@/components/soc/EventModal.vue'
import EventTable from '@/components/soc/EventTable.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const tab = ref(route.query.tab === 'incidents' ? 'incidents' : 'alerts')
const canTriage = computed(() => auth.can('blueteam.alerts.triage'))
const canRespond = computed(() => auth.can('incident.respond'))
const canViewInc = computed(() => auth.can('incident.view'))

// ------------------------------------------------------------------ alert queue
const f = reactive({ status: 'open', severity: route.query.severity ?? '', q: '', mine: false, demo: true })
const page = ref(1)
const alerts = ref(null)
const err = ref(null)
async function loadAlerts() {
  try {
    alerts.value = await api('/soc/alerts', { query: { status: f.status, severity: f.severity, q: f.q, mine: f.mine, include_demo: f.demo, page: page.value, page_size: 50 } })
    err.value = null
  } catch (e) { err.value = e }
}
watch(() => ({ ...f }), () => { page.value = 1; loadAlerts() })
watch(page, loadAlerts)

const alert = ref(null)
const assignees = ref([])
const resolution = ref('')
const selectedEvent = ref(null)
const playbooks = ref([])
const alertRuns = ref([])
const pbSel = ref('')
async function loadAlertRuns(id) {
  if (!canViewInc.value) return
  try {
    alertRuns.value = (await api('/soar/runs', { query: { alert_id: id } })).items
    if (canRespond.value && !playbooks.value.length) playbooks.value = (await api('/soar/playbooks')).items.filter((p) => p.is_enabled)
  } catch { alertRuns.value = [] }
}
async function runPlaybook() {
  try {
    const r = await api('/soar/runs', { method: 'POST', body: { playbook_id: Number(pbSel.value), alert_id: alert.value.id } })
    ui.success(r.status === 'awaiting_approval' ? `Run #${r.id} menunggu persetujuan` : `Run #${r.id} ${r.status === 'completed' ? 'selesai' : r.status}`)
    router.push({ name: 'soar', query: { run: r.id } })
  } catch (e) { ui.error(e) }
}
async function openAlert(id) {
  try {
    alert.value = await api(`/soc/alerts/${id}`); resolution.value = alert.value.resolution || ''
    loadAlertRuns(id)
    router.replace({ query: { ...route.query, alert: id } })
    if (canTriage.value && !assignees.value.length) assignees.value = await api('/soc/assignees')
  } catch (e) { ui.error(e) }
}
function closeAlert() { alert.value = null; const { alert: _a, ...q } = route.query; router.replace({ query: q }) }
async function patchAlert(body, msg) {
  try { await api(`/soc/alerts/${alert.value.id}`, { method: 'PATCH', body }); ui.success(msg); await openAlert(alert.value.id); loadAlerts() } catch (e) { ui.error(e) }
}
const escalateOpen = ref(false)
const esc = reactive({ mode: 'new', title: '', incident_id: null })
const openIncidents = ref([])
async function startEscalate() {
  esc.title = alert.value.title; esc.mode = 'new'; esc.incident_id = null
  try { openIncidents.value = await api('/soc/incidents') } catch { openIncidents.value = [] }
  escalateOpen.value = true
}
async function escalate() {
  try {
    const r = await api(`/soc/alerts/${alert.value.id}/escalate`, { method: 'POST', body: esc.mode === 'new' ? { title: esc.title } : { incident_id: esc.incident_id } })
    escalateOpen.value = false; ui.success(`Ditautkan ke insiden #${r.incident_id}`); router.push({ name: 'incident-detail', params: { id: r.incident_id } })
  } catch (e) { ui.error(e) }
}

// ------------------------------------------------------------------ incidents
const incStatus = ref('active')
const incidents = ref(null)
async function loadIncidents() { if (!canViewInc.value) return; try { incidents.value = await api('/soc/incidents', { query: { status: incStatus.value } }) } catch (e) { ui.error(e) } }
watch(incStatus, loadIncidents)
watch(tab, (t) => { router.replace({ query: { ...route.query, tab: t === 'incidents' ? 'incidents' : undefined } }); if (t === 'incidents') loadIncidents() })
const newInc = ref(null)
async function createIncident() {
  try { const i = await api('/soc/incidents', { method: 'POST', body: newInc.value }); newInc.value = null; router.push({ name: 'incident-detail', params: { id: i.id } }) } catch (e) { ui.error(e) }
}

onMounted(() => { loadAlerts(); if (tab.value === 'incidents') loadIncidents(); if (route.query.alert) openAlert(Number(route.query.alert)) })
</script>

<template>
  <PageHeader section="Blue Team Operations" title="Respons Insiden" subtitle="Triase antrean alert, eskalasi ke insiden dan tangani hingga selesai. Setiap tindakan diaudit.">
    <div class="flex rounded-md border border-ink-700 p-0.5" role="tablist">
      <button v-for="t in [['alerts', 'Antrean alert'], ['incidents', 'Incidents']]" :key="t[0]" role="tab" :aria-selected="tab === t[0]" :disabled="t[0] === 'incidents' && !canViewInc"
        :class="['rounded px-3 py-1 text-xs disabled:opacity-40', tab === t[0] ? 'bg-ink-700 text-ink-100' : 'text-ink-400 hover:text-ink-200']" @click="tab = t[0]">{{ t[1] }}</button>
    </div>
    <CrButton v-if="tab === 'incidents' && canRespond" variant="primary" @click="newInc = { title: '', summary: '', severity: 2 }"><Plus class="size-4" /> Insiden baru</CrButton>
  </PageHeader>

  <template v-if="tab === 'alerts'">
    <div class="panel mb-4 flex flex-wrap items-center gap-2 p-3">
      <div class="relative w-64"><Search class="absolute top-2.5 left-3 size-4 text-ink-500" /><input v-model.lazy="f.q" class="input pl-9" placeholder="Filter berdasarkan judul, IP, pengguna" aria-label="Filter alert" /></div>
      <select v-model="f.status" class="input w-40" aria-label="Status"><option value="open">Buka</option><option value="all">Semua</option><option v-for="s in ['new', 'acknowledged', 'in_progress', 'resolved', 'false_positive']" :key="s" :value="s">{{ $st(s) }}</option></select>
      <select v-model="f.severity" class="input w-36" aria-label="Severity minimum"><option value="">Semua severity</option><option v-for="(s, i) in SEVERITIES" :key="s" :value="i">≥ {{ s }}</option></select>
      <label class="flex items-center gap-1.5 text-xs text-ink-300"><input v-model="f.mine" type="checkbox" class="accent-cyan-400" /> ditugaskan ke saya</label>
      <label class="flex items-center gap-1.5 text-xs text-ink-300"><input v-model="f.demo" type="checkbox" class="accent-cyan-400" /> sertakan DEMO</label>
      <div v-if="alerts" class="ml-auto flex gap-2 font-mono text-[11px] text-ink-400"><span v-for="(n, s) in alerts.counts" :key="s">{{ s }} {{ n }}</span></div>
    </div>
    <div class="panel">
      <CrState v-if="err" kind="error" :message="err.message" @retry="loadAlerts" />
      <CrState v-else-if="!alerts" kind="loading" />
      <CrState v-else-if="!alerts.items.length" kind="empty" message="Tidak ada alert yang cocok. Alert muncul saat rule deteksi terpicu oleh event yang masuk." />
      <template v-else>
        <table class="data-table">
          <thead><tr><th>Alert</th><th>Severity</th><th>Status</th><th>Event</th><th>Terakhir terlihat</th><th>Penanggung jawab</th><th>Insiden</th></tr></thead>
          <tbody>
            <tr v-for="a in alerts.items" :key="a.id" class="cursor-pointer" :data-alert="a.id" @click="openAlert(a.id)">
              <td><div class="text-ink-100">{{ a.title }} <DemoTag v-if="a.is_demo" /></div><div class="font-mono text-[11px] text-ink-500">#{{ a.id }} · {{ a.rule_code }} · {{ a.mitre_technique || '' }}</div></td>
              <td><SevBadge :sev="a.severity" /></td>
              <td><CrBadge :tone="ALERT_STATUS_TONE[a.status]">{{ $st(a.status) }}</CrBadge></td>
              <td class="font-mono text-xs">{{ a.event_count }}</td>
              <td class="font-mono text-xs text-ink-400">{{ ago(a.last_seen) }}</td>
              <td class="text-xs">{{ a.assignee || '—' }}</td>
              <td class="font-mono text-xs">{{ a.incident_id ? `#${a.incident_id}` : '—' }}</td>
            </tr>
          </tbody>
        </table>
        <div class="border-t border-ink-700/60 p-2"><CrPagination v-model:page="page" :total="alerts.total" :page-size="alerts.page_size" /></div>
      </template>
    </div>
  </template>

  <template v-else>
    <div class="mb-3 flex gap-2"><select v-model="incStatus" class="input w-44" aria-label="Status insiden"><option value="active">Aktif</option><option value="all">Semua</option><option value="closed">Ditutup</option></select></div>
    <div class="panel">
      <CrState v-if="!incidents" kind="loading" />
      <CrState v-else-if="!incidents.length" kind="empty" message="Belum ada insiden. Eskalasi alert atau buka insiden secara manual." />
      <table v-else class="data-table">
        <thead><tr><th>Insiden</th><th>Severity</th><th>Status</th><th>Alerts</th><th>Pemilik</th><th>Diperbarui</th></tr></thead>
        <tbody>
          <tr v-for="i in incidents" :key="i.id" class="cursor-pointer" :data-incident="i.id" @click="router.push({ name: 'incident-detail', params: { id: i.id } })">
            <td><div class="text-ink-100">{{ i.title }} <DemoTag v-if="i.is_demo" /></div><div class="font-mono text-[11px] text-ink-500">INC-{{ i.id }} · opened {{ fmtTime(i.created_at) }}</div></td>
            <td><SevBadge :sev="i.severity" /></td><td><CrBadge :tone="INCIDENT_TONE[i.status]">{{ $st(i.status) }}</CrBadge></td>
            <td class="font-mono text-xs">{{ i.alert_count }}</td><td class="text-xs">{{ i.owner || '—' }}</td><td class="font-mono text-xs text-ink-400">{{ ago(i.updated_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>

  <CrModal :open="!!alert" :title="alert ? `Alert #${alert.id}` : ''" width="max-w-4xl" @close="closeAlert">
    <div v-if="alert" class="space-y-3">
      <div class="flex flex-wrap items-center gap-2"><SevBadge :sev="alert.severity" /><CrBadge :tone="ALERT_STATUS_TONE[alert.status]" data-test="alert-status">{{ $st(alert.status) }}</CrBadge><DemoTag v-if="alert.is_demo" />
        <span class="text-sm text-ink-100">{{ alert.title }}</span></div>
      <p class="text-xs text-ink-400">{{ alert.rule_code }} · {{ alert.rule }} — {{ alert.rule_description }}<span v-if="alert.mitre_technique"> · MITRE {{ alert.mitre_tactic }} / {{ alert.mitre_technique }}</span></p>
      <div class="grid grid-cols-2 gap-2 font-mono text-[11px] text-ink-400 md:grid-cols-4">
        <div>pertama {{ fmtTime(alert.first_seen) }}</div><div>terakhir {{ fmtTime(alert.last_seen) }}</div><div>{{ alert.event_count }} event</div><div>penanggung jawab {{ alert.assignee || '—' }}</div>
      </div>
      <div v-if="alert.resolution" class="rounded border border-ink-700 p-2 text-xs"><b>Penyelesaian:</b> {{ alert.resolution }}</div>
      <div v-if="canTriage" class="flex flex-wrap items-center gap-2 rounded border border-ink-700 p-2">
        <CrButton size="sm" @click="patchAlert({ assign_to_me: true }, 'Ditugaskan ke Anda')"><UserCheck class="size-3.5" /> Tugaskan ke saya</CrButton>
        <select class="input h-8 w-44 text-xs" aria-label="Tugaskan ke" @change="(e) => e.target.value && patchAlert({ assignee_id: Number(e.target.value) }, 'Penanggung jawab diperbarui')">
          <option value="">Tugaskan ke…</option><option v-for="u in assignees" :key="u.id" :value="u.id">{{ u.username }}</option></select>
        <CrButton v-if="alert.status !== 'in_progress'" size="sm" @click="patchAlert({ status: 'in_progress' }, 'Ditandai sedang ditangani')">Sedang berjalan</CrButton>
        <input v-model="resolution" class="input h-8 min-w-48 flex-1 text-xs" placeholder="Catatan penyelesaian (wajib untuk menutup)" aria-label="Catatan penyelesaian" />
        <CrButton size="sm" :disabled="!resolution.trim()" @click="patchAlert({ status: 'resolved', resolution }, 'Alert diselesaikan')">Selesaikan</CrButton>
        <CrButton size="sm" variant="ghost" :disabled="!resolution.trim()" @click="patchAlert({ status: 'false_positive', resolution }, 'Ditutup sebagai false positive')">False positive</CrButton>
        <CrButton v-if="canRespond" size="sm" variant="primary" @click="startEscalate"><ArrowUpRight class="size-3.5" /> {{ alert.incident_id ? 'Pindahkan ke insiden' : 'Eskalasi' }}</CrButton>
      </div>
      <RouterLink v-if="alert.incident_id" :to="{ name: 'incident-detail', params: { id: alert.incident_id } }" class="text-xs text-accent-300 hover:underline">Bagian dari insiden INC-{{ alert.incident_id }}</RouterLink>
      <div v-if="canViewInc" class="flex flex-wrap items-center gap-2 rounded border border-ink-700 p-2 text-xs" data-test="alert-soar">
        <span class="font-medium text-ink-200">SOAR</span>
        <template v-if="canRespond">
          <select v-model="pbSel" class="input h-8 w-64 text-xs" aria-label="Pilih playbook"><option value="">Pilih playbook…</option>
            <option v-for="p in playbooks" :key="p.id" :value="p.id">{{ p.code }} · {{ p.name }}</option></select>
          <CrButton size="sm" :disabled="!pbSel" data-test="run-playbook" @click="runPlaybook"><Workflow class="size-3.5" /> Jalankan</CrButton>
        </template>
        <RouterLink v-for="r in alertRuns" :key="r.id" :to="{ name: 'soar', query: { run: r.id } }" class="text-accent-300 underline">Run #{{ r.id }} ({{ r.playbook.code }}: {{ $st(r.status) }})</RouterLink>
        <span v-if="!alertRuns.length" class="text-ink-500">Belum ada playbook dijalankan untuk alert ini.</span>
      </div>
      <div class="max-h-80 overflow-auto rounded border border-ink-700"><EventTable :items="alert.events" compact @select="selectedEvent = $event.id" /></div>
    </div>
  </CrModal>
  <EventModal :event-id="selectedEvent" @close="selectedEvent = null" @pivot="(t) => router.push({ name: 'siem', query: { q: t } })" />

  <CrModal :open="escalateOpen" title="Eskalasi ke insiden" @close="escalateOpen = false">
    <div class="space-y-3">
      <label class="flex items-center gap-2 text-sm"><input v-model="esc.mode" type="radio" value="new" class="accent-cyan-400" /> Buka insiden baru</label>
      <input v-if="esc.mode === 'new'" v-model="esc.title" class="input" aria-label="Judul insiden" />
      <label class="flex items-center gap-2 text-sm"><input v-model="esc.mode" type="radio" value="existing" class="accent-cyan-400" :disabled="!openIncidents.length" /> Tambah ke insiden terbuka</label>
      <select v-if="esc.mode === 'existing'" v-model="esc.incident_id" class="input" aria-label="Insiden"><option v-for="i in openIncidents" :key="i.id" :value="i.id">INC-{{ i.id }} {{ i.title }}</option></select>
    </div>
    <template #footer><CrButton @click="escalateOpen = false">Batal</CrButton><CrButton variant="primary" :disabled="esc.mode === 'new' ? esc.title.trim().length < 3 : !esc.incident_id" @click="escalate">Eskalasi</CrButton></template>
  </CrModal>
  <CrModal :open="!!newInc" title="Insiden baru" @close="newInc = null">
    <div v-if="newInc" class="space-y-3">
      <div><label class="field-label" for="ni-title">Judul</label><input id="ni-title" v-model="newInc.title" class="input" /></div>
      <div><label class="field-label" for="ni-sev">Severity</label><select id="ni-sev" v-model.number="newInc.severity" class="input"><option v-for="(s, i) in SEVERITIES" :key="s" :value="i">{{ s }}</option></select></div>
      <div><label class="field-label" for="ni-sum">Ringkasan</label><textarea id="ni-sum" v-model="newInc.summary" class="input" rows="3" /></div>
    </div>
    <template #footer><CrButton @click="newInc = null">Batal</CrButton><CrButton variant="primary" :disabled="(newInc?.title || '').trim().length < 3" @click="createIncident">Buat</CrButton></template>
  </CrModal>
</template>
