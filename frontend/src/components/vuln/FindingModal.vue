<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import SevBadge from '@/components/soc/SevBadge.vue'
import { STATUS_LABEL, STATUS_TONE, TASK_TONE, evidenceText } from './vuln'

const props = defineProps({ id: Number })
const emit = defineEmits(['close', 'changed'])
const auth = useAuthStore()
const ui = useUiStore()
const canManage = computed(() => auth.can('vuln.manage'))
const f = ref(null)
const users = ref([])
async function load() {
  if (!props.id) { f.value = null; return }
  try { f.value = await api(`/vuln/findings/${props.id}`) } catch (e) { ui.error(e); emit('close') }
}
watch(() => props.id, async (id) => {
  await load()
  if (id && canManage.value && !users.value.length) users.value = await api('/vuln/assignees').catch(() => [])
}, { immediate: true })
const st = reactive({ status: '', reason: '', until: '' })
const busy = ref(false)
async function setStatus() {
  busy.value = true
  try {
    await api(`/vuln/findings/${f.value.id}/status`, { method: 'POST', body: { status: st.status, reason: st.reason, risk_accepted_until: st.until || null } })
    ui.success('Status diperbarui'); Object.assign(st, { status: '', reason: '', until: '' }); await load(); emit('changed')
  } catch (e) { ui.error(e) } finally { busy.value = false }
}
const task = reactive({ title: '', assignee_id: '', due_date: '', notes: '' })
async function addTask() {
  try {
    await api(`/vuln/findings/${f.value.id}/tasks`, { method: 'POST', body: { title: task.title, assignee_id: task.assignee_id || null, due_date: task.due_date || null, notes: task.notes } })
    ui.success('Tugas remediasi dibuat'); Object.assign(task, { title: '', assignee_id: '', due_date: '', notes: '' }); await load(); emit('changed')
  } catch (e) { ui.error(e) }
}
async function taskStatus(t, status) {
  try { await api(`/vuln/tasks/${t.id}`, { method: 'PATCH', body: { status } }); await load(); emit('changed') } catch (e) { ui.error(e) }
}
async function setOwner(ev) {
  try { await api(`/vuln/findings/${f.value.id}/owner`, { method: 'POST', body: { owner_id: ev.target.value ? Number(ev.target.value) : null } }); await load() } catch (e) { ui.error(e) }
}
const needsReason = computed(() => ['false_positive', 'risk_accepted'].includes(st.status))
</script>

<template>
  <CrModal :open="!!id" :title="f ? `${f.vulnerability.code} · ${f.vulnerability.title}` : 'Temuan'" width="max-w-4xl" @close="emit('close')">
    <div v-if="f" class="space-y-4 text-sm" data-test="finding-detail">
      <div class="flex flex-wrap items-center gap-2"><SevBadge :sev="f.severity" /><CrBadge :tone="STATUS_TONE[f.status]" data-test="finding-status">{{ STATUS_LABEL[f.status] }}</CrBadge>
        <CrBadge v-for="c in f.vulnerability.cves" :key="c" tone="high">{{ c }}</CrBadge><CrBadge v-if="f.vulnerability.detection === 'version'" tone="warn">berbasis versi · konfirmasi</CrBadge><CrBadge>{{ f.source }}</CrBadge>
        <span class="text-xs text-ink-400">{{ f.asset }} ({{ f.node_key }}) {{ f.ip }}{{ f.port ? `:${f.port}` : '' }} · lab <RouterLink :to="{ name: 'lab-detail', params: { id: f.lab_id } }" class="text-accent-300 hover:underline">{{ f.lab }}</RouterLink></span></div>
      <div class="grid gap-3 md:grid-cols-2">
        <div class="rounded border border-ink-700 p-3"><div class="field-label">Deskripsi</div><p class="text-xs text-ink-300">{{ f.vulnerability_detail.description }}</p>
          <div class="field-label mt-2">Remediasi</div><p class="text-xs text-ink-300">{{ f.vulnerability_detail.remediation }}</p>
          <div v-if="f.vulnerability_detail.references.length" class="mt-2 text-xs"><a v-for="r in f.vulnerability_detail.references" :key="r" :href="r" target="_blank" rel="noopener noreferrer" class="block truncate text-accent-300 hover:underline">{{ r }}</a></div></div>
        <div class="rounded border border-ink-700 p-3"><div class="field-label">Evidence teramati</div><p class="break-words font-mono text-[11px] text-ink-200" data-test="finding-evidence">{{ evidenceText(f.evidence) }}</p>
          <div class="mt-2 text-xs text-ink-400">first {{ fmtTime(f.first_seen) }} · last {{ ago(f.last_seen) }} · seen {{ f.times_seen }}× <span v-if="f.last_job_id">· last scan #{{ f.last_job_id }}</span></div>
          <div v-if="f.status_reason" class="mt-1 text-xs text-ink-400">Reason: {{ f.status_reason }}<span v-if="f.risk_accepted_until"> (hingga {{ f.risk_accepted_until }})</span></div>
          <div class="mt-2 flex items-center gap-2 text-xs"><span class="text-ink-400">Pemilik</span>
            <select v-if="canManage" class="input h-7 w-44 text-xs" :value="f.owner_id || ''" aria-label="Pemilik" @change="setOwner"><option value="">belum ditugaskan</option><option v-for="u in users" :key="u.id" :value="u.id">{{ u.username }}</option></select>
            <span v-else>{{ f.owner || 'unassigned' }}</span></div></div>
      </div>
      <section v-if="canManage && f.allowed_transitions.length" class="rounded border border-ink-700 p-3">
        <div class="field-label">Ubah status</div>
        <div class="flex flex-wrap items-end gap-2">
          <select v-model="st.status" class="input w-56" aria-label="Status baru" data-test="status-select"><option value="" disabled>Pilih…</option><option v-for="s in f.allowed_transitions" :key="s" :value="s">{{ STATUS_LABEL[s] }}</option></select>
          <input v-model="st.reason" class="input flex-1" :placeholder="needsReason ? 'Justifikasi (wajib, 10+ karakter)' : 'Alasan (opsional)'" aria-label="Alasan" />
          <input v-if="st.status === 'risk_accepted'" v-model="st.until" type="date" class="input w-40" aria-label="Diterima hingga" />
          <CrButton :disabled="!st.status || (needsReason && st.reason.trim().length < 10) || (st.status === 'risk_accepted' && !st.until)" :loading="busy" data-test="apply-status" @click="setStatus">Terapkan</CrButton>
        </div>
        <p v-if="st.status === 'fixed_pending_verification' && f.source === 'scan'" class="mt-1 text-xs text-ink-500">Scan berikutnya yang mencakup aset dan port ini memverifikasi perbaikan: tidak terdeteksi → selesai, masih terdeteksi → dibuka kembali.</p>
      </section>
      <section>
        <h4 class="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-400">Tugas remediasi</h4>
        <table v-if="f.tasks.length" class="data-table" data-test="finding-tasks"><thead><tr><th>Tugas</th><th>Penanggung jawab</th><th>Tenggat</th><th>Status</th><th /></tr></thead>
          <tbody><tr v-for="t in f.tasks" :key="t.id"><td>{{ t.title }}<div v-if="t.notes" class="text-xs text-ink-500">{{ t.notes }}</div></td><td class="text-xs">{{ t.assignee || '—' }}</td>
            <td class="font-mono text-xs" :class="t.overdue ? 'text-sev-critical' : ''">{{ t.due_date || '—' }}</td><td><CrBadge :tone="TASK_TONE[t.status]">{{ $st(t.status) }}</CrBadge></td>
            <td class="text-right"><template v-if="canManage && ['open', 'in_progress'].includes(t.status)"><CrButton v-if="t.status === 'open'" size="sm" variant="ghost" @click="taskStatus(t, 'in_progress')">Mulai</CrButton>
              <CrButton size="sm" data-test="task-done" @click="taskStatus(t, 'done')">Selesai</CrButton></template></td></tr></tbody></table>
        <p v-else class="text-xs text-ink-500">Tidak ada tugas.</p>
        <form v-if="canManage && !['resolved', 'false_positive'].includes(f.status)" class="mt-2 grid gap-2 md:grid-cols-[1fr_10rem_9rem_auto]" @submit.prevent="addTask">
          <input v-model="task.title" class="input" placeholder="Apa yang harus dilakukan" aria-label="Judul tugas" data-test="task-title" />
          <select v-model="task.assignee_id" class="input" aria-label="Penanggung jawab"><option value="">belum ditugaskan</option><option v-for="u in users" :key="u.id" :value="u.id">{{ u.username }}</option></select>
          <input v-model="task.due_date" type="date" class="input" aria-label="Tanggal tenggat" />
          <CrButton type="submit" :disabled="task.title.trim().length < 3" data-test="add-task">Tambah tugas</CrButton></form>
      </section>
      <section><h4 class="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-400">Riwayat</h4>
        <ol class="space-y-1 text-xs"><li v-for="h in f.history" :key="h.id" class="flex gap-2"><span class="font-mono text-ink-500">{{ fmtTime(h.at) }}</span><CrBadge>{{ $st(h.kind) }}</CrBadge><span class="text-ink-300">{{ $tr(h.message) }}</span></li></ol></section>
    </div>
  </CrModal>
</template>
