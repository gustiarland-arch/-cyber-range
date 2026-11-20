<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Plus } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { STATUS_TONE, isLive, statusLabel } from '@/components/redteam/rt'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import RequestAssessmentModal from '@/components/redteam/RequestAssessmentModal.vue'

const props = defineProps({ mode: { type: String, default: 'simulation' } }) // simulation | workspace
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const rows = ref(null)
const err = ref(null)
const status = ref(props.mode === 'workspace' && auth.can('redteam.assessment.approve') ? 'awaiting_me' : 'all')
const reqOpen = ref(!!route.query.scenario)
let timer = null
async function load() {
  try { rows.value = await api('/redteam/assessments', { query: { status: status.value } }); err.value = null } catch (e) { err.value = e }
  clearTimeout(timer); timer = setTimeout(load, (rows.value || []).some((a) => isLive(a.status)) ? 2000 : 15000)
}
watch(status, load)
onMounted(load)
onBeforeUnmount(() => clearTimeout(timer))
function created(a) { reqOpen.value = false; router.push({ name: 'assessment', params: { id: a.id } }) }
const FILTERS = [['all', 'All'], ['active', 'Active'], ['awaiting_me', 'Menunggu persetujuan saya'], ['completed', 'Completed'], ['rejected', 'Rejected']]
</script>

<template>
  <PageHeader section="Red Team Operations" :title="mode === 'workspace' ? 'Workspace Assessment Terotorisasi' : 'Simulasi Serangan'"
    :subtitle="mode === 'workspace' ? 'Tinjau cakupan, setujui atau tolak permintaan dengan catatan otorisasi, dan kumpulkan laporan.' : 'Ajukan, jalankan dan pantau simulasi non-destruktif di dalam lab terisolasi Anda.'">
    <CrButton v-if="auth.can('redteam.assessment.request')" variant="primary" @click="reqOpen = true"><Plus class="size-4" /> Ajukan assessment</CrButton>
  </PageHeader>
  <div v-if="mode === 'workspace'" class="panel mb-4 grid gap-3 p-4 text-sm md:grid-cols-3">
    <div><div class="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-400">Kebijakan otorisasi</div><p class="text-xs text-ink-400">Persetujuan wajib dan dikunci oleh kebijakan. Pemohon tidak dapat menyetujui permintaannya sendiri. Persetujuan berakhir bersama jendela waktunya.</p></div>
    <div><div class="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-400">Pengikatan cakupan</div><p class="text-xs text-ink-400">Target diterjemahkan ke alamat satu deployment lab tertentu. Redeploy, stop atau kill switch membatalkan eksekusi.</p></div>
    <div><div class="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-400">Aksi yang diizinkan</div><p class="text-xs text-ink-400">Host discovery, TCP connect scan, inventaris HTTP, pemeriksaan segmentasi. Tidak ada yang destruktif, tanpa kredensial, tanpa payload.</p></div>
  </div>
  <div class="mb-3 flex flex-wrap gap-1">
    <button v-for="f in FILTERS" :key="f[0]" :class="['rounded-md border px-3 py-1 text-xs', status === f[0] ? 'border-accent-500/60 bg-accent-500/10 text-accent-300' : 'border-ink-700 text-ink-400 hover:text-ink-200']" @click="status = f[0]">{{ f[1] }}</button>
  </div>
  <div class="panel">
    <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
    <CrState v-else-if="!rows" kind="loading" />
    <CrState v-else-if="!rows.length" kind="empty" :message="status === 'awaiting_me' ? 'Tidak ada permintaan yang menunggu persetujuan Anda.' : 'Belum ada assessment.'" />
    <table v-else class="data-table">
      <thead><tr><th>Assessment</th><th>Status</th><th>Lab / penyerang</th><th>Target</th><th>Jendela waktu (lokal)</th><th>Diajukan</th><th>Temuan</th></tr></thead>
      <tbody>
        <tr v-for="a in rows" :key="a.id" class="cursor-pointer" :data-assessment="a.title" @click="router.push({ name: 'assessment', params: { id: a.id } })">
          <td><div class="text-ink-100">{{ a.title }}</div><div class="font-mono text-[11px] text-ink-500">#{{ a.id }} · {{ a.scenario.code }} {{ a.scenario.name }}</div></td>
          <td><CrBadge :tone="STATUS_TONE[a.status]">{{ statusLabel(a.status) }}</CrBadge></td>
          <td class="text-xs">{{ a.lab }}<div class="font-mono text-[11px] text-ink-500">{{ a.attacker_node }} {{ a.attacker_ip }}</div></td>
          <td class="text-xs">{{ a.targets.map((t) => t.label).join(', ') }}</td>
          <td class="font-mono text-[11px] text-ink-400">{{ fmtTime(a.window_start) }}<br />{{ fmtTime(a.window_end) }}</td>
          <td class="text-xs">{{ a.requested_by }}<div class="font-mono text-[10px] text-ink-500">{{ ago(a.created_at) }}</div></td>
          <td class="font-mono text-xs">{{ a.finding_count }}</td>
        </tr>
      </tbody>
    </table>
  </div>
  <RequestAssessmentModal :open="reqOpen" :scenario-id="route.query.scenario ? Number(route.query.scenario) : null" @close="reqOpen = false" @created="created" />
</template>
