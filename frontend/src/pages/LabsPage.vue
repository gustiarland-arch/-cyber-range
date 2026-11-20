<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Plus, Power, Rocket, Search, ShieldOff } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import { STATUS_LABEL, STATUS_TONE, isBusy } from '@/components/labs/labStatus'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrKpi from '@/components/ui/CrKpi.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const auth = useAuthStore()
const ui = useUiStore()
const router = useRouter()
const data = ref(null)
const err = ref(null)
const q = ref('')
let timer = null

async function load() {
  try { data.value = await api('/labs'); err.value = null } catch (e) { err.value = e }
  clearTimeout(timer)
  timer = setTimeout(load, (data.value?.labs || []).some((l) => isBusy(l.status)) ? 2000 : 10000)
}
onMounted(load)
onBeforeUnmount(() => clearTimeout(timer))

const labs = computed(() => (data.value?.labs || []).filter((l) => l.name.toLowerCase().includes(q.value.toLowerCase())))
const kpi = computed(() => {
  const all = data.value?.labs || []
  const running = all.filter((l) => l.status === 'running')
  return {
    total: all.length, running: running.length, failed: all.filter((l) => l.status === 'failed').length,
    containers: running.reduce((s, l) => s + (l.instance?.containers.length || 0), 0),
  }
})

const canOperate = computed(() => auth.can('lab.operate'))
const createOpen = ref(false)
const networks = ref([])
const form = reactive({ network_id: null, name: '', description: '' })
const creating = ref(false)
const createErrors = ref([])
async function openCreate() {
  createErrors.value = []
  try { networks.value = await api('/networks') } catch (e) { return ui.error(e) }
  form.network_id = networks.value[0]?.id ?? null
  form.name = ''
  createOpen.value = true
}
async function create() {
  if (!form.network_id || !form.name.trim()) return ui.error('Pilih jaringan dan nama')
  creating.value = true; createErrors.value = []
  try {
    const lab = await api('/labs', { method: 'POST', body: form })
    ui.success(`Lab ${lab.name} dibuat`)
    router.push({ name: 'lab-detail', params: { id: lab.id } })
  } catch (e) {
    createErrors.value = Array.isArray(e.details) ? e.details.map((d) => (typeof d === 'string' ? d : d.message)) : [e.message]
  } finally { creating.value = false }
}

const ksOpen = ref(false)
const ksReason = ref('')
async function toggleKill() {
  try {
    await api('/labs/kill-switch', { method: 'POST', body: { engaged: !data.value.kill_switch, reason: ksReason.value } })
    ui.success(data.value.kill_switch ? 'Kill switch dilepas' : 'Kill switch aktif: lab yang berjalan sedang dihentikan')
    ksOpen.value = false; ksReason.value = ''; load()
  } catch (e) { ui.error(e) }
}
</script>

<template>
  <PageHeader section="Cyber Range Lab" title="Lab Manager" subtitle="Deploy topologi sebagai lab container terisolasi: jaringan internal saja, container yang di-hardening, kuota dan kill switch global.">
    <CrButton v-if="auth.can('lab.killswitch') && data" :variant="data.kill_switch ? 'secondary' : 'danger'" @click="ksOpen = true">
      <Power class="size-4" /> {{ data.kill_switch ? 'Lepas kill switch' : 'Kill switch' }}
    </CrButton>
    <CrButton v-if="canOperate" variant="primary" @click="openCreate"><Plus class="size-4" /> Lab baru</CrButton>
  </PageHeader>

  <div v-if="data?.kill_switch" class="mb-4 flex items-center gap-3 rounded-lg border border-sev-critical/50 bg-sev-critical/10 p-3 text-sm text-sev-critical" role="alert" data-test="kill-banner">
    <ShieldOff class="size-5 shrink-0" />
    <div><b>Kill switch aktif.</b> Semua lab yang berjalan telah dihentikan dan tidak ada lab yang boleh deploy, start, reset atau restore sampai Anda melepasnya di halaman ini.</div>
  </div>

  <div class="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
    <CrKpi label="Labs" :value="kpi.total" />
    <CrKpi label="Berjalan" :value="kpi.running" tone="ok" />
    <CrKpi label="Gagal" :value="kpi.failed" :tone="kpi.failed ? 'bad' : undefined" />
    <CrKpi label="Container aktif" :value="kpi.containers" />
  </div>

  <div class="panel">
    <div class="border-b border-ink-700/60 p-3"><div class="relative w-72"><Search class="absolute top-2.5 left-3 size-4 text-ink-500" /><input v-model="q" class="input pl-9" placeholder="Filter lab" aria-label="Filter lab" /></div></div>
    <CrState v-if="err && !data" kind="error" :message="err.message" @retry="load" />
    <CrState v-else-if="!data" kind="loading" />
    <CrState v-else-if="!labs.length" kind="empty" :message="canOperate ? 'Buat lab dari topologi jaringan yang tervalidasi.' : 'Tidak ada lab yang terlihat oleh Anda.'">
      <CrButton v-if="canOperate" size="sm" variant="primary" @click="openCreate"><Rocket class="size-3.5" /> Buat lab pertama</CrButton>
    </CrState>
    <table v-else class="data-table">
      <thead><tr><th>Lab</th><th>Pemilik</th><th>Status</th><th>Container</th><th>Jaringan</th><th>Sumber daya</th><th>Diperbarui</th></tr></thead>
      <tbody>
        <tr v-for="l in labs" :key="l.id" class="cursor-pointer" :data-lab="l.name" @click="router.push({ name: 'lab-detail', params: { id: l.id } })">
          <td><div class="text-ink-100">{{ l.name }}</div><div class="font-mono text-[11px] text-ink-500">network #{{ l.network_id }} v{{ l.network_version }}<span v-if="l.instance"> · {{ l.instance.runtime_id }}</span></div></td>
          <td class="text-xs">{{ l.owner }}</td>
          <td><CrBadge :tone="STATUS_TONE[l.status]" data-test="status">{{ STATUS_LABEL[l.status] || l.status }}</CrBadge></td>
          <td class="font-mono text-xs">{{ l.instance ? `${l.instance.containers.filter((c) => c.status === 'running').length}/${l.instance.containers.length}` : `0/${l.totals.containers}` }}</td>
          <td class="font-mono text-xs">{{ l.totals.networks }}</td>
          <td class="font-mono text-xs">{{ l.totals.cpus }} vCPU · {{ l.totals.memory_mb }} MB</td>
          <td class="font-mono text-xs text-ink-400">{{ ago(l.updated_at) }}</td>
        </tr>
      </tbody>
    </table>
  </div>

  <CrModal :open="createOpen" title="Lab baru" @close="createOpen = false">
    <div class="space-y-3">
      <div v-if="!networks.length" class="rounded border border-warn/40 bg-warn/5 p-3 text-sm text-warn" data-test="no-networks">
        Belum ada topologi jaringan. Buat jaringan dulu di <RouterLink :to="{ name: 'networks' }" class="font-semibold underline" @click="createOpen = false">Topologi Jaringan</RouterLink>
        (pilih template atau mulai kosong, lalu Simpan), kemudian kembali ke sini.</div>
      <div v-else><label class="field-label" for="lab-net">Topologi jaringan</label>
        <select id="lab-net" v-model="form.network_id" class="input">
          <option v-for="n in networks" :key="n.id" :value="n.id">{{ n.name }} · v{{ n.version }} · {{ $st(n.validation_status) }}</option>
        </select>
        <p class="mt-1 text-xs text-ink-500">Topologi dibekukan ke lab pada versi ini. Topologi dengan error validasi tidak dapat di-deploy.</p></div>
      <div><label class="field-label" for="lab-name">Nama lab</label><input id="lab-name" v-model="form.name" class="input" maxlength="128" /></div>
      <div><label class="field-label" for="lab-desc">Deskripsi</label><textarea id="lab-desc" v-model="form.description" class="input" rows="2" /></div>
      <ul v-if="createErrors.length" class="max-h-40 overflow-y-auto rounded border border-sev-critical/40 bg-sev-critical/5 p-2 text-xs text-sev-critical" role="alert"><li v-for="(e, i) in createErrors" :key="i">{{ e }}</li></ul>
    </div>
    <template #footer><CrButton @click="createOpen = false">Batal</CrButton><CrButton variant="primary" :loading="creating" :disabled="!networks.length" @click="create">Buat lab</CrButton></template>
  </CrModal>

  <CrModal :open="ksOpen" :title="data?.kill_switch ? 'Lepas kill switch' : 'Aktifkan kill switch'" @close="ksOpen = false">
    <p class="mb-3 text-sm">{{ data?.kill_switch ? 'Lab akan diizinkan berjalan kembali.' : 'Semua lab yang berjalan di platform langsung dihentikan dan tidak ada lab yang boleh dimulai sampai kill switch dilepas.' }} Tindakan ini diaudit.</p>
    <label class="field-label" for="ks-reason">Alasan</label><input id="ks-reason" v-model="ksReason" class="input" maxlength="500" />
    <template #footer><CrButton @click="ksOpen = false">Batal</CrButton>
      <CrButton :variant="data?.kill_switch ? 'primary' : 'danger'" :disabled="ksReason.trim().length < 3" @click="toggleKill">{{ data?.kill_switch ? 'Lepas' : 'Aktifkan' }}</CrButton></template>
  </CrModal>
</template>
