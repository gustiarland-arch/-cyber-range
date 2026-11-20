<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/services/api'
import { fmtTime } from '@/services/format'
import { ALERT_STATUS_TONE, INCIDENT_STATUSES, INCIDENT_TONE, SEVERITIES } from '@/services/soc'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const inc = ref(null)
const err = ref(null)
const note = ref('')
const nextStatus = ref('')
const canRespond = computed(() => auth.can('incident.respond'))
async function load() { try { inc.value = await api(`/soc/incidents/${route.params.id}`); err.value = null } catch (e) { err.value = e } }
onMounted(load)
async function patch(body, msg) {
  try { inc.value = await api(`/soc/incidents/${inc.value.id}`, { method: 'PATCH', body }); note.value = ''; nextStatus.value = ''; ui.success(msg) } catch (e) { ui.error(e) }
}
function submit() {
  if (nextStatus.value) patch({ status: nextStatus.value, note: note.value || undefined }, `Status: ${nextStatus.value}`)
  else patch({ note: note.value }, 'Catatan ditambahkan')
}
const KIND_LABEL = { created: 'dibuka', alert_linked: 'alert ditautkan', alert_updated: 'alert diperbarui', status: 'status', severity: 'severity', assigned: 'pemilik', note: 'catatan' }
</script>

<template>
  <CrState v-if="err" :kind="err.status === 404 ? 'empty' : 'error'" :message="err.message" @retry="load" />
  <CrState v-else-if="!inc" kind="loading" />
  <template v-else>
    <PageHeader section="Respons Insiden" :title="`INC-${inc.id} · ${inc.title}`" :subtitle="inc.summary">
      <DemoTag v-if="inc.is_demo" /><SevBadge :sev="inc.severity" /><CrBadge :tone="INCIDENT_TONE[inc.status]" data-test="incident-status">{{ $st(inc.status) }}</CrBadge>
    </PageHeader>
    <div class="grid gap-4 xl:grid-cols-3">
      <div class="space-y-4 xl:col-span-2">
        <CrPanel title="Timeline" :padded="false">
          <ol class="divide-y divide-ink-800" data-test="timeline">
            <li v-for="e in inc.timeline" :key="e.id" class="flex gap-3 px-4 py-2">
              <span class="w-36 shrink-0 font-mono text-[11px] text-ink-500">{{ fmtTime(e.at) }}</span>
              <CrBadge>{{ KIND_LABEL[e.kind] || e.kind }}</CrBadge>
              <div class="min-w-0 flex-1 text-sm text-ink-200"><span class="whitespace-pre-wrap">{{ e.body }}</span><span class="ml-2 text-xs text-ink-500">{{ e.author }}</span></div>
            </li>
          </ol>
          <div v-if="canRespond && inc.status !== 'closed'" class="space-y-2 border-t border-ink-700/60 p-3">
            <textarea v-model="note" class="input" rows="2" placeholder="Tambah catatan: temuan, tindakan yang diambil, keputusan" aria-label="Catatan" />
            <div class="flex flex-wrap items-center gap-2">
              <select v-model="nextStatus" class="input w-48" aria-label="Ubah status"><option value="">Pertahankan status</option><option v-for="s in INCIDENT_STATUSES.filter((x) => x !== inc.status)" :key="s" :value="s">→ {{ s }}</option></select>
              <span v-if="nextStatus === 'closed'" class="text-xs text-ink-500">Catatan penutupan wajib diisi.</span>
              <CrButton variant="primary" class="ml-auto" :disabled="!note.trim() && !nextStatus" @click="submit">{{ nextStatus ? 'Perbarui status' : 'Tambah catatan' }}</CrButton>
            </div>
          </div>
        </CrPanel>
        <CrPanel title="Alert terkait" :padded="false">
          <CrState v-if="!inc.alerts.length" kind="empty" message="Tidak ada alert terkait." />
          <table v-else class="data-table">
            <thead><tr><th>Alert</th><th>Severity</th><th>Status</th><th>Event</th><th>Jendela waktu</th></tr></thead>
            <tbody><tr v-for="a in inc.alerts" :key="a.id" class="cursor-pointer" @click="router.push({ name: 'incident-response', query: { alert: a.id } })">
              <td><div class="text-ink-100">{{ a.title }}</div><div class="font-mono text-[11px] text-ink-500">#{{ a.id }} {{ a.rule_code }} {{ a.mitre_technique || '' }}</div></td>
              <td><SevBadge :sev="a.severity" /></td><td><CrBadge :tone="ALERT_STATUS_TONE[a.status]">{{ $st(a.status) }}</CrBadge></td>
              <td class="font-mono text-xs">{{ a.event_count }}</td><td class="font-mono text-[11px] text-ink-400">{{ fmtTime(a.first_seen) }} → {{ fmtTime(a.last_seen) }}</td>
            </tr></tbody>
          </table>
        </CrPanel>
      </div>
      <div class="space-y-4">
        <CrPanel title="Detail">
          <dl class="space-y-2 text-sm">
            <div class="flex justify-between"><dt class="text-ink-500">Pemilik</dt><dd>{{ inc.owner || '—' }}</dd></div>
            <div class="flex justify-between"><dt class="text-ink-500">Dibuka</dt><dd class="font-mono text-xs">{{ fmtTime(inc.created_at) }}</dd></div>
            <div class="flex justify-between"><dt class="text-ink-500">Event pertama</dt><dd class="font-mono text-xs">{{ inc.first_event_at ? fmtTime(inc.first_event_at) : '—' }}</dd></div>
            <div v-if="inc.closed_at" class="flex justify-between"><dt class="text-ink-500">Ditutup</dt><dd class="font-mono text-xs">{{ fmtTime(inc.closed_at) }}</dd></div>
            <div v-if="canRespond && inc.status !== 'closed'" class="flex items-center justify-between"><dt class="text-ink-500">Severity</dt>
              <dd><select :value="inc.severity" class="input h-8 w-32 text-xs" aria-label="Severity" @change="(e) => patch({ severity: Number(e.target.value) }, 'Severity diperbarui')">
                <option v-for="(s, i) in SEVERITIES" :key="s" :value="i">{{ s }}</option></select></dd></div>
          </dl>
        </CrPanel>
        <CrPanel title="Indikator" subtitle="Diturunkan dari event di balik alert yang terhubung.">
          <div v-for="(vals, k) in inc.indicators" :key="k" class="mb-3">
            <div class="mb-1 text-[10px] uppercase tracking-wider text-ink-500">{{ k.replace('_', ' ') }}</div>
            <div v-if="!vals.length" class="text-xs text-ink-600">—</div>
            <RouterLink v-for="v in vals" :key="v" :to="{ name: 'siem', query: { q: `${{ src_ips: 'src', dst_ips: 'dst', users: 'user', hosts: 'host' }[k]}:${v}`, range: '7d' } }"
              class="mr-1 mb-1 inline-block rounded border border-ink-700 px-1.5 py-0.5 font-mono text-[11px] text-ink-200 hover:border-accent-500">{{ v }}</RouterLink>
          </div>
        </CrPanel>
      </div>
    </div>
  </template>
</template>
