<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Boxes, Camera, Radar, Download, History, Network, Play, RotateCcw, Rocket, Square, SquareTerminal, Trash2, Undo2, X, XOctagon } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { ago, fmtTime as dt } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import { STATUS_LABEL, STATUS_TONE, allowedActions, fmtBytes, isBusy } from '@/components/labs/labStatus'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import LabTerminal from '@/terminal/LabTerminal.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const lab = ref(null)
const err = ref(null)
const busy = ref(false)
let timer = null

async function load() {
  try { lab.value = await api(`/labs/${route.params.id}`); err.value = null } catch (e) { err.value = e }
  clearTimeout(timer)
  if (lab.value) timer = setTimeout(load, isBusy(lab.value.status) || lab.value.snapshots.some((s) => s.status === 'creating') ? 1500 : 10000)
}
onMounted(load)
onBeforeUnmount(() => clearTimeout(timer))
watch(() => route.params.id, () => { lab.value = null; load() })

const can = computed(() => (lab.value ? allowedActions(lab.value.status) : {}))
const termNode = ref(null)
const termSessions = ref([])
const canTerminal = computed(() => auth.can('lab.terminal') && operable.value && lab.value?.status === 'running')
async function loadSessions() {
  if (!auth.can('lab.terminal')) return
  try { termSessions.value = await api(`/terminal/labs/${route.params.id}/sessions`) } catch { termSessions.value = [] }
}
onMounted(loadSessions)
function openTerminal(n) { termNode.value = { key: n.node_key, label: n.label } }
function onTermClosed() { loadSessions() }
async function getTranscript(s) {
  try { await download(`/terminal/sessions/${s.id}/transcript`, undefined, `terminal-${s.id}-${s.node_key}.log`) } catch (e) { ui.error(e) }
}
const operable = computed(() => auth.can('lab.operate') && lab.value && (lab.value.owner_id === auth.user?.id || auth.can('lab.manage')))
const stats = computed(() => lab.value?.instance?.stats?.containers || {})
const containersByKey = computed(() => Object.fromEntries((lab.value?.instance?.containers || []).map((c) => [c.node_key, c])))
const planRows = computed(() => (lab.value?.plan.containers || []).map((p) => ({ ...p, live: containersByKey.value[p.node_key] })))

async function run(path, body, okMsg) {
  busy.value = true
  try {
    const r = await api(`/labs/${lab.value.id}${path}`, { method: 'POST', body })
    if (r?.plan) lab.value = r
    ui.success(okMsg)
  } catch (e) { ui.error(e) } finally { busy.value = false; load() }
}
const confirm = ref(null) // { title, text, action, danger }
function ask(kind) {
  const m = {
    reset: { title: 'Reset lab', text: 'Semua container dibuat ulang dari image bersihnya. Perubahan di dalam lab akan hilang (snapshot tetap disimpan).', run: () => run('/reset', undefined, 'Lab reset') },
    destroy: { title: 'Hancurkan lab', text: 'Container dan jaringan terisolasi dihapus. Snapshot tetap tersedia untuk deployment baru lab ini.', run: () => run('/destroy', undefined, 'Lab destroyed'), danger: true },
    delete: { title: 'Hapus lab', text: 'Definisi lab dihapus secara soft-delete. Jejak auditnya tetap disimpan.', danger: true, run: async () => {
      try { await api(`/labs/${lab.value.id}`, { method: 'DELETE' }); ui.success('Lab dihapus'); router.push({ name: 'labs' }) } catch (e) { ui.error(e) }
    } },
  }
  confirm.value = m[kind]
}
async function doConfirm() { const c = confirm.value; confirm.value = null; await c.run() }

const snapOpen = ref(false)
const snapName = ref('')
async function snapshot() { snapOpen.value = false; await run('/snapshots', { name: snapName.value }, 'Snapshot diminta'); snapName.value = '' }
const restoreTarget = ref(null)

async function restore() { const s = restoreTarget.value; restoreTarget.value = null; await run(`/snapshots/${s.id}/restore`, undefined, `Restored ${s.name}`) }
async function delSnap(s) { try { await api(`/labs/${lab.value.id}/snapshots/${s.id}`, { method: 'DELETE' }); ui.success('Snapshot dihapus'); load() } catch (e) { ui.error(e) } }

const levelTone = { info: 'neutral', warn: 'warn', error: 'bad' }

// network sensors (Zeek / Suricata) on the lab's isolated bridges
const sensors = ref([])
const sensorForm = ref(null)
async function loadSensors() { try { sensors.value = (await api(`/labs/${route.params.id}/sensors`)).sensors } catch { sensors.value = [] } }
onMounted(loadSensors)
watch(() => lab.value?.status, loadSensors)
const activeSensors = computed(() => sensors.value.filter((s) => ['pending', 'starting', 'running', 'failed', 'stopping'].includes(s.status)))
const SENSOR_LABEL = { zeek: 'Zeek', suricata: 'Suricata', agent: 'Host agent' }
const nodeLabel = (key) => lab.value?.plan?.containers?.find((c) => c.node_key === key)?.label || key
function openSensors() { sensorForm.value = { zeek: true, suricata: true, subnets: lab.value.plan.networks.map((n) => n.subnet_key) } }
async function attachSensors() {
  const f = sensorForm.value
  const kinds = ['zeek', 'suricata'].filter((k) => f[k])
  sensorForm.value = null
  busy.value = true
  try { sensors.value = (await api(`/labs/${lab.value.id}/sensors`, { method: 'POST', body: { kinds, subnets: f.subnets } })).sensors; ui.success('Sensor diminta') } catch (e) { ui.error(e) } finally { busy.value = false; load() }
}
async function detachSensor(s) {
  try { sensors.value = (await api(`/labs/${lab.value.id}/sensors`, { method: 'DELETE', query: s ? { sensor_id: s.id } : undefined })).sensors; ui.success('Sensor dihentikan') } catch (e) { ui.error(e) }
}
const subnetName = (k) => lab.value?.plan.networks.find((n) => n.subnet_key === k)?.name || k
</script>

<template>
  <CrState v-if="err && !lab" :kind="err.status === 404 ? 'empty' : 'error'" :title="err.status === 404 ? 'Lab tidak ditemukan' : undefined" :message="err.message" @retry="load" />
  <CrState v-else-if="!lab" kind="loading" />
  <template v-else>
    <PageHeader section="Lab Manager" :title="lab.name" :subtitle="lab.description || `Dari jaringan #${lab.network_id} v${lab.network_version} · pemilik ${lab.owner}`">
      <CrBadge :tone="STATUS_TONE[lab.status]" class="!text-xs" data-test="lab-status">{{ STATUS_LABEL[lab.status] || lab.status }}</CrBadge>
      <RouterLink :to="{ name: 'lab-3d', params: { id: lab.id } }" data-test="open-lab-3d"
        class="inline-flex h-9 items-center gap-1.5 rounded-md border border-accent-400/40 bg-accent-500/10 px-3 text-sm text-accent-300 hover:bg-accent-500/20"><Boxes class="size-4" /> Tampilan 3D hidup</RouterLink>
      <template v-if="operable">
        <CrButton v-if="can.deploy" variant="primary" :loading="busy" @click="run('/deploy', undefined, 'Deploy dimulai')"><Rocket class="size-4" /> Deploy</CrButton>
        <CrButton v-if="can.start" variant="primary" :loading="busy" @click="run('/start', undefined, 'Lab started')"><Play class="size-4" /> Mulai</CrButton>
        <CrButton v-if="can.stop" :loading="busy" @click="run('/stop', undefined, 'Lab stopped')"><Square class="size-4" /> Hentikan</CrButton>
        <CrButton v-if="can.snapshot" :disabled="busy" @click="snapOpen = true"><Camera class="size-4" /> Snapshot</CrButton>
        <CrButton v-if="can.reset" :disabled="busy" @click="ask('reset')"><RotateCcw class="size-4" /> Reset</CrButton>
        <CrButton v-if="can.destroy" variant="danger" :disabled="busy" @click="ask('destroy')"><XOctagon class="size-4" /> Hancurkan</CrButton>
        <CrButton v-if="can.delete" variant="ghost" title="Hapus lab" @click="ask('delete')"><Trash2 class="size-4" /></CrButton>
      </template>
      <CrButton variant="ghost" title="Buka topologi dalam 3D" @click="router.push({ name: 'network-3d', params: { id: lab.network_id } })"><Boxes class="size-4" /></CrButton>
    </PageHeader>

    <div v-if="lab.instance?.error" class="mb-4 rounded-lg border border-sev-critical/40 bg-sev-critical/5 p-3 font-mono text-xs text-sev-critical" role="alert">{{ lab.instance.error }}</div>

    <div class="grid gap-4 xl:grid-cols-3">
      <div class="space-y-4 xl:col-span-2">
        <CrPanel title="Node" :padded="false" :subtitle="`${lab.totals.containers} container · ${lab.totals.cpus} vCPU · ${lab.totals.memory_mb} MB`">
          <table class="data-table">
            <thead><tr><th>Node</th><th>Image</th><th>Alamat</th><th>Kondisi</th><th>CPU</th><th>Memori</th><th v-if="canTerminal"><span class="sr-only">Terminal</span></th></tr></thead>
            <tbody>
              <tr v-for="n in planRows" :key="n.node_key" :data-node="n.node_key">
                <td><div class="text-ink-100">{{ n.label }}</div><div class="font-mono text-[11px] text-ink-500">{{ n.type }}<span v-if="n.fallback"> · VM dalam mode kompatibel</span><span v-if="n.ip_forward"> · meneruskan</span></div></td>
                <td class="font-mono text-xs">{{ n.live?.image?.startsWith('sha256:') ? 'snapshot' : n.image }}</td>
                <td class="font-mono text-xs"><div v-for="a in n.attachments" :key="a.subnet_key">{{ n.live?.addresses?.[a.subnet_key] || a.ip || 'dhcp' }} <span class="text-ink-500">{{ a.subnet_key }}</span></div></td>
                <td><CrBadge v-if="n.live" :tone="n.live.status === 'running' ? 'ok' : n.live.status === 'missing' ? 'bad' : 'neutral'">{{ $st(n.live.status) }}</CrBadge><span v-else class="text-xs text-ink-500">—</span></td>
                <td class="font-mono text-xs">{{ stats[n.node_key] ? `${stats[n.node_key].cpu_pct}%` : '—' }}</td>
                <td class="font-mono text-xs">{{ stats[n.node_key] ? `${fmtBytes(stats[n.node_key].mem_bytes)} / ${n.memory_mb} MB` : `${n.memory_mb} MB` }}</td>
                <td v-if="canTerminal" class="text-right">
                  <CrButton size="sm" variant="ghost" :disabled="n.live?.status !== 'running'" :data-terminal="n.node_key" @click="openTerminal(n)"><SquareTerminal class="size-3.5" /> Terminal</CrButton>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-if="lab.plan.skipped.length" class="border-t border-ink-700/60 p-3 text-xs text-ink-400">
            <div v-for="s in lab.plan.skipped" :key="s.node_key">Belum di-deploy: <b class="text-ink-200">{{ s.label }}</b> · {{ $tr(s.reason) }}</div>
          </div>
          <div v-if="lab.status === 'running'" class="border-t border-ink-700/60 px-3 py-2 text-[11px] text-ink-500">
            Metrik langsung {{ lab.instance.stats ? `diambil ${ago(lab.instance.stats.at)}` : 'belum diambil (lab worker mengambil sampel tiap 10 dtk)' }}
          </div>
        </CrPanel>

        <CrPanel title="Jaringan terisolasi" :padded="false" subtitle="Bridge khusus internal: tanpa NAT, tanpa egress, tanpa alamat host di bridge.">
          <table class="data-table">
            <thead><tr><th>Subnet</th><th>CIDR</th><th>Jaringan runtime</th><th>Egress</th></tr></thead>
            <tbody>
              <tr v-for="n in lab.plan.networks" :key="n.subnet_key">
                <td class="text-ink-100">{{ n.name }}</td><td class="font-mono text-xs">{{ n.cidr }}</td>
                <td class="font-mono text-xs text-ink-400">{{ lab.instance?.networks.find((x) => x.subnet_key === n.subnet_key)?.name || '—' }}</td>
                <td><CrBadge tone="ok">diblokir</CrBadge></td>
              </tr>
            </tbody>
          </table>
        </CrPanel>

        <CrPanel title="Sensor jaringan & host agent" :padded="false" subtitle="Zeek dan Suricata menangkap lalu lintas bridge lab secara pasif. Node lab kantor (domain controller, portal, workstation) punya host agent yang mengirim log proses, login, file, web dan autentikasi domain. Semuanya otomatis masuk ke SIEM." data-test="sensors-panel">
          <template #actions>
            <CrButton v-if="operable && lab.status === 'running'" size="sm" data-test="sensor-attach" @click="openSensors"><Radar class="size-3.5" /> Pasang sensor</CrButton>
            <CrButton v-if="operable && activeSensors.some((s) => s.kind !== 'agent')" size="sm" variant="ghost" @click="detachSensor(null)">Hentikan sensor jaringan</CrButton>
          </template>
          <CrState v-if="!activeSensors.length" kind="empty" :message="lab.status === 'running' ? 'Belum ada sensor. Pasang Zeek/Suricata agar serangan di lab terlihat sebagai telemetri jaringan nyata.' : 'Sensor dapat dipasang saat lab berjalan.'" />
          <table v-else class="data-table">
            <thead><tr><th>Sensor</th><th>Jaringan / node</th><th>Status</th><th>Event</th><th /></tr></thead>
            <tbody><tr v-for="s in activeSensors" :key="s.id" :data-sensor="s.kind">
              <td><div class="text-ink-100">{{ SENSOR_LABEL[s.kind] || s.kind }}</div><div class="font-mono text-[11px] text-ink-500">{{ s.image }}{{ s.kind === 'agent' ? '' : ` · ${s.interface}` }}</div></td>
              <td class="text-xs">{{ s.kind === 'agent' ? nodeLabel(s.subnet_key) : subnetName(s.subnet_key) }}</td>
              <td><CrBadge :tone="s.status === 'running' ? 'ok' : s.status === 'failed' ? 'bad' : 'accent'">{{ $st(s.status) }}</CrBadge><div v-if="s.error" class="mt-1 max-w-xs text-[11px] text-sev-critical">{{ s.error }}</div></td>
              <td class="font-mono text-xs">{{ s.events_total }}<div v-if="s.last_event_at" class="text-[10px] text-ink-500">{{ ago(s.last_event_at) }}</div></td>
              <td class="text-right"><RouterLink v-if="s.log_source_id && auth.can('blueteam.alerts.view')" :to="{ name: 'siem', query: { q: `source:${s.log_source_id}` } }" class="mr-2 text-xs text-accent-300 hover:underline">SIEM</RouterLink>
                <CrButton v-if="operable" size="sm" variant="ghost" @click="detachSensor(s)">Hentikan</CrButton></td>
            </tr></tbody>
          </table>
        </CrPanel>
      </div>

      <div class="space-y-4">
        <CrPanel title="Snapshot" :padded="false">
          <CrState v-if="!lab.snapshots.length" kind="empty" message="Buat snapshot lab yang berjalan atau berhenti untuk menyimpan kondisinya." />
          <ul v-else class="divide-y divide-ink-700/60">
            <li v-for="s in lab.snapshots" :key="s.id" class="flex items-center gap-2 px-3 py-2" :data-snapshot="s.name">
              <History class="size-4 text-ink-500" />
              <div class="min-w-0 flex-1"><div class="truncate text-sm text-ink-100">{{ s.name }}</div>
                <div class="font-mono text-[11px] text-ink-500">{{ dt(s.created_at) }} · {{ s.nodes }} nodes</div>
                <div v-if="s.error" class="text-[11px] text-sev-critical">{{ s.error }}</div></div>
              <CrBadge :tone="s.status === 'ready' ? 'ok' : s.status === 'failed' ? 'bad' : 'accent'">{{ $st(s.status) }}</CrBadge>
              <template v-if="operable">
                <CrButton v-if="s.status === 'ready' && can.reset" size="sm" variant="ghost" title="Pulihkan" @click="restoreTarget = s"><Undo2 class="size-3.5" /></CrButton>
                <CrButton v-if="s.status !== 'creating'" size="sm" variant="ghost" title="Hapus snapshot" @click="delSnap(s)"><Trash2 class="size-3.5" /></CrButton>
              </template>
            </li>
          </ul>
        </CrPanel>

        <CrPanel v-if="auth.can('lab.terminal')" title="Sesi terminal" :padded="false" subtitle="Setiap sesi tercatat di audit log beserta transkripnya (SHA-256).">
          <CrState v-if="!termSessions.length" kind="empty" title="Belum ada sesi" message="Buka terminal dari tabel node saat lab berjalan." />
          <ul v-else class="max-h-72 divide-y divide-ink-800 overflow-y-auto text-xs" data-test="terminal-sessions">
            <li v-for="t in termSessions" :key="t.id" class="flex items-center gap-2 px-3 py-2">
              <CrBadge :tone="t.status === 'active' ? 'ok' : t.status === 'denied' ? 'bad' : 'neutral'">{{ $st(t.status) }}</CrBadge>
              <span class="font-mono text-ink-200">#{{ t.id }} {{ t.node_key }}</span>
              <span class="truncate text-ink-500">{{ t.user }} · {{ ago(t.issued_at) }}<span v-if="t.end_reason"> · {{ $tr(t.end_reason) }}</span></span>
              <CrButton v-if="t.transcript" class="ml-auto" size="sm" variant="ghost" title="Unduh transkrip" @click="getTranscript(t)"><Download class="size-3.5" /></CrButton>
            </li>
          </ul>
        </CrPanel>

        <CrPanel title="Event" :padded="false">
          <ol class="max-h-[32rem] divide-y divide-ink-800 overflow-y-auto" data-test="events">
            <li v-for="e in lab.events" :key="e.id" class="px-3 py-2">
              <div class="flex items-center gap-2"><CrBadge :tone="levelTone[e.level]">{{ e.kind }}</CrBadge><span class="ml-auto font-mono text-[10px] text-ink-500" :title="dt(e.at)">{{ ago(e.at) }}</span></div>
              <div class="mt-1 text-xs text-ink-300">{{ $tr(e.message) }}</div>
            </li>
          </ol>
        </CrPanel>
      </div>
    </div>

    <section v-if="termNode" class="fixed inset-x-0 bottom-0 z-40 flex h-[45vh] flex-col border-t border-accent-400/40 bg-ink-900 shadow-2xl lg:left-[var(--sidebar-w,16rem)]" aria-label="Terminal lab" data-test="terminal-drawer">
      <div class="flex items-center gap-2 px-3 py-1 text-xs text-ink-400"><SquareTerminal class="size-3.5 text-accent-400" /> Terminal lab · {{ lab.name }}
        <button class="ml-auto rounded p-1 hover:bg-ink-800 hover:text-ink-100" aria-label="Tutup panel terminal" @click="termNode = null; loadSessions()"><X class="size-4" /></button></div>
      <LabTerminal class="min-h-0 flex-1" :lab-id="lab.id" :node-key="termNode.key" :label="termNode.label" :key="termNode.key" @closed="onTermClosed" @opened="loadSessions" />
    </section>

    <CrModal :open="!!confirm" :title="confirm?.title" @close="confirm = null">
      <p class="text-sm">{{ confirm?.text }} Tindakan ini diaudit.</p>
      <template #footer><CrButton @click="confirm = null">Batal</CrButton><CrButton :variant="confirm?.danger ? 'danger' : 'primary'" @click="doConfirm">{{ confirm?.title }}</CrButton></template>
    </CrModal>
    <CrModal :open="snapOpen" title="Ambil snapshot" @close="snapOpen = false">
      <label class="field-label" for="snap-name">Nama</label><input id="snap-name" v-model="snapName" class="input" maxlength="128" placeholder="mis. sebelum-latihan" />
      <p class="mt-2 text-xs text-ink-500">Filesystem setiap container di-commit ke image lokal. Container yang berjalan dijeda sebentar.</p>
      <template #footer><CrButton @click="snapOpen = false">Batal</CrButton><CrButton variant="primary" :disabled="!/^[\w .:-]+$/.test(snapName)" @click="snapshot">Snapshot</CrButton></template>
    </CrModal>
    <CrModal :open="!!restoreTarget" title="Pulihkan snapshot" @close="restoreTarget = null">
      <p class="text-sm">Buat ulang setiap container dari snapshot <b class="text-ink-100">{{ restoreTarget?.name }}</b>? Perubahan saat ini akan hilang.</p>
      <template #footer><CrButton @click="restoreTarget = null">Batal</CrButton><CrButton variant="primary" @click="restore">Pulihkan</CrButton></template>
    </CrModal>
  </template>
</template>
