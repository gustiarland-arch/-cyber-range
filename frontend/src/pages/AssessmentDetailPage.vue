<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { CheckCircle2, Circle, FileDown, Film, LoaderCircle, Play, Square, XCircle } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import { STATUS_TONE, isLive, statusLabel } from '@/components/redteam/rt'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const a = ref(null)
const err = ref(null)
let timer = null
async function load() {
  try { a.value = await api(`/redteam/assessments/${route.params.id}`); err.value = null } catch (e) { err.value = e }
  clearTimeout(timer); if (a.value && isLive(a.value.status)) timer = setTimeout(load, 1500)
}
onMounted(load)
onBeforeUnmount(() => clearTimeout(timer))

const mine = computed(() => a.value?.requested_by_id === auth.user?.id)
// Local edition: the single operator authorises their own request with a written note (the server enforces >= 10 characters).
const canDecide = computed(() => a.value?.status === 'pending_approval' && auth.can('redteam.assessment.approve'))
const canRun = computed(() => a.value?.status === 'approved' && mine.value && auth.can('redteam.assessment.execute'))
const canAbort = computed(() => ['pending_approval', 'approved', 'queued', 'running'].includes(a.value?.status) && (mine.value || auth.can('redteam.assessment.approve') || auth.can('lab.killswitch')))
const hasReport = computed(() => ['completed', 'aborted', 'failed'].includes(a.value?.status))
function stepState(i) {
  const tl = a.value.timeline
  if (tl.some((e) => e.kind === 'step_finished' && e.step === i)) return 'done'
  if (tl.some((e) => e.kind === 'step_started' && e.step === i)) return ['failed', 'aborted'].includes(a.value.status) ? 'failed' : 'running'
  return 'pending'
}
const stepSummary = (i) => a.value.timeline.find((e) => e.kind === 'step_finished' && e.step === i)?.message
async function post(path, body, msg) {
  try { a.value = await api(`/redteam/assessments/${a.value.id}${path}`, { method: 'POST', body }); ui.success(msg); load() } catch (e) { ui.error(e) }
}
const decision = ref(null)
const comment = ref('')
async function decide() { await post('/decision', { approve: decision.value, comment: comment.value }, decision.value ? 'Assessment disetujui' : 'Assessment ditolak'); decision.value = null; comment.value = '' }
const confirmRun = ref(false)
</script>

<template>
  <CrState v-if="err" :kind="err.status === 404 ? 'empty' : 'error'" :message="err.message" @retry="load" />
  <CrState v-else-if="!a" kind="loading" />
  <template v-else>
    <PageHeader section="Red Team Operations" :title="`#${a.id} · ${a.title}`" :subtitle="`${a.scenario.code} ${a.scenario.name} · lab ${a.lab} (${a.runtime_id})`">
      <CrBadge :tone="STATUS_TONE[a.status]" class="!text-xs" data-test="rt-status">{{ statusLabel(a.status) }}</CrBadge>
      <template v-if="canDecide"><CrButton variant="primary" @click="decision = true">Setujui</CrButton><CrButton variant="danger" @click="decision = false">Tolak</CrButton></template>
      <CrButton v-if="canRun" variant="primary" @click="confirmRun = true"><Play class="size-4" /> Jalankan</CrButton>
      <CrButton v-if="canAbort" variant="danger" @click="post('/abort', undefined, 'Penghentian diminta')"><Square class="size-4" /> {{ ['queued', 'running'].includes(a.status) ? 'Batalkan' : 'Batal' }}</CrButton>
      <CrButton v-if="hasReport" @click="download(`/redteam/assessments/${a.id}/report`, null, `assessment-${a.id}-report.md`)"><FileDown class="size-4" /> Laporan</CrButton>
      <CrButton v-if="hasReport" variant="ghost" title="Replay" @click="router.push({ name: 'attack-timeline', query: { id: a.id } })"><Film class="size-4" /></CrButton>
    </PageHeader>
    <div v-if="a.status === 'pending_approval' && mine" class="mb-4 rounded-lg border border-warn/40 bg-warn/5 p-3 text-sm text-warn">Menunggu otorisasi. Periksa cakupan, lalu klik Setujui dan tulis catatan otorisasi, atau Tolak.</div>
    <div v-if="a.error" class="mb-4 rounded-lg border border-sev-critical/40 bg-sev-critical/5 p-3 font-mono text-xs text-sev-critical">{{ a.error }}</div>
    <div class="grid gap-4 xl:grid-cols-3">
      <div class="space-y-4 xl:col-span-2">
        <CrPanel title="Langkah" :padded="false">
          <ol class="divide-y divide-ink-800" data-test="rt-steps">
            <li v-for="(s, i) in a.steps" :key="i" class="flex items-start gap-3 px-4 py-3" :data-step="stepState(i)">
              <CheckCircle2 v-if="stepState(i) === 'done'" class="mt-0.5 size-4 text-ok" />
              <LoaderCircle v-else-if="stepState(i) === 'running'" class="mt-0.5 size-4 animate-spin text-accent-400" />
              <XCircle v-else-if="stepState(i) === 'failed'" class="mt-0.5 size-4 text-sev-critical" />
              <Circle v-else class="mt-0.5 size-4 text-ink-600" />
              <div class="min-w-0 flex-1"><div class="text-sm text-ink-100">{{ i + 1 }}. {{ s.title }}</div>
                <div class="font-mono text-[11px] text-ink-500">{{ s.action }} · {{ s.tactic }} {{ s.mitre }} <span v-if="s.params?.ports">· ports {{ s.params.ports.join(', ') }}</span><span v-if="s.params?.paths"> · paths {{ s.params.paths.join(' ') }}</span></div>
                <div v-if="stepSummary(i)" class="mt-1 text-xs text-ink-300">{{ $tr(stepSummary(i)) }}</div>
                <div v-if="a.purple?.[i]?.attacked" class="mt-1 flex flex-wrap items-center gap-1.5 text-[11px]" :data-purple="a.purple[i].detected ? 'detected' : 'missed'">
                  <CrBadge :tone="a.purple[i].detected_same_technique ? 'ok' : a.purple[i].detected ? 'warn' : 'bad'">{{ a.purple[i].detected_same_technique ? 'terdeteksi' : a.purple[i].detected ? 'terdeteksi rule lain' : 'tidak terdeteksi' }}</CrBadge>
                  <span v-for="al in a.purple[i].alerts" :key="al.id" class="font-mono text-ink-400">#{{ al.id }} {{ al.rule }} <span class="text-ink-500">({{ al.sources.map((x) => (x === 'sensor' ? 'sensor' : 'aktivitas platform')).join(', ') }})</span></span>
                </div></div>
            </li>
          </ol>
        </CrPanel>
        <CrPanel :title="`Findings (${a.findings.length})`" :padded="false">
          <CrState v-if="!a.findings.length" kind="empty" :message="hasReport ? 'Tidak ada temuan: tidak ada yang terjangkau atau terekspos untuk langkah ini.' : 'Temuan muncul saat langkah selesai.'" />
          <table v-else class="data-table"><thead><tr><th>Severity</th><th>Temuan</th><th>Target</th><th>Langkah</th></tr></thead>
            <tbody><tr v-for="f in a.findings" :key="f.id" :data-finding="f.kind"><td><SevBadge :sev="f.severity" /></td><td class="text-ink-100">{{ f.title }}<div v-if="f.detail?.server" class="font-mono text-[11px] text-ink-500">Server: {{ f.detail.server }}</div></td>
              <td class="font-mono text-xs">{{ f.target_ip }}{{ f.port ? `:${f.port}` : '' }}</td><td class="font-mono text-xs">{{ f.step + 1 }}</td></tr></tbody></table>
        </CrPanel>
      </div>
      <div class="space-y-4">
        <CrPanel title="Otorisasi">
          <dl class="space-y-1.5 text-xs">
            <div class="flex justify-between gap-2"><dt class="text-ink-500">Diajukan oleh</dt><dd>{{ a.requested_by }}</dd></div>
            <div class="flex justify-between gap-2"><dt class="text-ink-500">Keputusan</dt><dd>{{ a.decided_by ? `${a.decided_by} · ${fmtTime(a.decided_at)}` : '—' }}</dd></div>
            <div v-if="a.decision_comment" class="rounded border border-ink-700 p-2 text-ink-300">“{{ a.decision_comment }}”</div>
            <div class="flex justify-between gap-2"><dt class="text-ink-500">Jendela waktu</dt><dd class="text-right font-mono">{{ fmtTime(a.window_start) }}<br />{{ fmtTime(a.window_end) }}</dd></div>
            <div class="pt-1 text-ink-400">{{ a.justification }}</div>
          </dl>
        </CrPanel>
        <CrPanel title="Cakupan">
          <div class="mb-2 text-xs text-ink-400">Penyerang <b class="text-ink-200">{{ a.attacker_node }}</b> <span class="font-mono">{{ a.attacker_ip }}</span></div>
          <ul class="space-y-1 text-xs"><li v-for="t in a.targets" :key="t.node_key" class="flex justify-between"><span class="text-ink-200">{{ t.label }}</span><span class="font-mono text-ink-400">{{ t.ips.join(', ') }}</span></li></ul>
          <div class="mt-2 font-mono text-[11px] text-ink-500">subnets {{ a.scope.cidrs.join(', ') }}</div>
        </CrPanel>
        <CrPanel title="Cakupan deteksi" subtitle="Alert SOC pada alamat penyerang selama run">
          <div v-if="!a.started_at" class="text-xs text-ink-500">Tersedia setelah eksekusi.</div>
          <div v-else-if="!a.detections.length" class="text-xs text-warn" data-test="detections">Tidak ada alert yang muncul. Blue team tidak mendeteksi aktivitas ini.</div>
          <ul v-else class="space-y-1 text-xs" data-test="detections"><li v-for="d in a.detections" :key="d.id"><RouterLink :to="{ name: 'incident-response', query: { alert: d.id } }" class="text-accent-300 hover:underline">#{{ d.id }} {{ d.rule }}</RouterLink> {{ d.title }}</li></ul>
        </CrPanel>
        <CrPanel title="Timeline" :padded="false">
          <ol class="max-h-96 divide-y divide-ink-800 overflow-y-auto"><li v-for="e in a.timeline" :key="e.id" class="px-4 py-2"><div class="flex justify-between"><CrBadge>{{ $st(e.kind) }}</CrBadge><span class="font-mono text-[10px] text-ink-500">{{ fmtTime(e.at) }}</span></div><div class="mt-1 text-xs text-ink-300">{{ $tr(e.message) }}</div></li></ol>
        </CrPanel>
      </div>
    </div>
    <CrModal :open="decision !== null" :title="decision ? 'Setujui assessment' : 'Tolak assessment'" @close="decision = null">
      <p class="mb-2 text-sm">Konfirmasi cakupan: {{ a.targets.length }} target di lab <b>{{ a.lab }}</b> dari {{ a.attacker_node }}, jendela hingga {{ fmtTime(a.window_end) }}.</p>
      <p v-if="decision" class="mb-2 text-xs text-ink-400">Edisi lokal: Anda menyetujui permintaan Anda sendiri. Tulis catatan otorisasi (minimal 10 karakter) bahwa target adalah lab terisolasi milik Anda.</p>
      <label class="field-label" for="dec-c">{{ decision ? 'Catatan otorisasi' : 'Alasan' }} (dicatat di audit log dan laporan)</label><textarea id="dec-c" v-model="comment" class="input" rows="2" data-test="decision-note" />
      <template #footer><CrButton @click="decision = null">Batal</CrButton><CrButton :variant="decision ? 'primary' : 'danger'" :disabled="comment.trim().length < (decision ? 10 : 3)" data-test="decision-confirm" @click="decide">{{ decision ? 'Setujui' : 'Tolak' }}</CrButton></template>
    </CrModal>
    <CrModal :open="confirmRun" title="Jalankan assessment" @close="confirmRun = false">
      <p class="text-sm">Run {{ a.steps.length }} langkah sekarang dari <b>{{ a.attacker_node }}</b>? Anda dapat membatalkan di antara langkah.</p>
      <template #footer><CrButton @click="confirmRun = false">Batal</CrButton><CrButton variant="primary" @click="confirmRun = false; post('/execute', undefined, 'Eksekusi dimulai')">Jalankan</CrButton></template>
    </CrModal>
  </template>
</template>
