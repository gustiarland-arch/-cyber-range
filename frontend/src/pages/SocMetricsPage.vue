<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { Clock, Gauge, Timer, TimerReset } from 'lucide-vue-next'
import { api } from '@/services/api'
import { dur, fmtTime } from '@/services/format'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const days = ref(30)
const demo = ref(true)
const data = ref(null)
const err = ref(null)
const loading = ref(false)
async function load() {
  loading.value = true
  try { data.value = await api('/soc/sla', { query: { days: days.value, include_demo: demo.value } }); err.value = null } catch (e) { err.value = e } finally { loading.value = false }
}
onMounted(load)
watch([days, demo], load)

const SEV_TONE = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'neutral' }
const pctTone = (p) => (p === null ? 'text-ink-500' : p >= 90 ? 'text-ok' : p >= 70 ? 'text-warn' : 'text-sev-critical')
const pct = (p) => (p === null ? '—' : `${p}%`)
const mins = (m) => dur(m * 60)
const kpis = computed(() => {
  const o = data.value?.overall
  if (!o) return []
  return [
    { icon: Clock, label: 'MTTD', hint: 'Rata-rata waktu dari event pertama sampai alert muncul', v: dur(o.mttd.mean_s), n: o.mttd.count },
    { icon: Timer, label: 'MTTA', hint: 'Rata-rata waktu sampai alert di-acknowledge analis', v: dur(o.mtta.mean_s), n: o.mtta.count },
    { icon: TimerReset, label: 'MTTR', hint: 'Rata-rata waktu sampai alert selesai (resolved / false positive)', v: dur(o.mttr.mean_s), n: o.mttr.count },
    { icon: Gauge, label: 'SLA acknowledge', hint: 'Persentase alert yang di-acknowledge sebelum batas waktu', v: pct(o.ack_sla_pct), tone: pctTone(o.ack_sla_pct) },
    { icon: Gauge, label: 'SLA resolve', hint: 'Persentase alert yang selesai sebelum batas waktu', v: pct(o.resolve_sla_pct), tone: pctTone(o.resolve_sla_pct) },
  ]
})
</script>

<template>
  <PageHeader section="Blue Team Operations" title="SLA & Metrik SOC" subtitle="Seberapa cepat tim mendeteksi, merespons, dan menyelesaikan alert. Semua angka dihitung dari waktu tercatat pada alert dan insiden.">
      <select v-model.number="days" class="input w-36" aria-label="Rentang waktu" data-test="sla-days"><option :value="7">7 hari</option><option :value="30">30 hari</option><option :value="90">90 hari</option></select>
      <label class="flex items-center gap-2 text-xs text-ink-300"><input v-model="demo" type="checkbox" class="accent-cyan-400" /> Sertakan DEMO</label>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!data" kind="loading" />
  <template v-else>
    <div class="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5" data-test="sla-kpis">
      <div v-for="k in kpis" :key="k.label" class="panel p-3" :title="k.hint" :data-kpi="k.label">
        <div class="flex items-center gap-2 text-xs text-ink-400"><component :is="k.icon" class="size-4" />{{ k.label }}</div>
        <div :class="['mt-1 text-2xl font-semibold', k.tone || 'text-ink-100']">{{ k.v }}</div>
        <div class="text-[11px] text-ink-500">{{ k.n !== undefined ? `${k.n} sampel` : k.hint }}</div>
      </div>
    </div>
    <CrState v-if="!data.alerts" kind="empty" message="Belum ada alert pada rentang waktu ini, jadi belum ada metrik untuk dihitung." />
    <div v-else class="grid gap-4 xl:grid-cols-5">
      <CrPanel title="Per severity" class="xl:col-span-3">
        <div class="overflow-x-auto">
          <table class="w-full text-sm" data-test="sla-table">
            <thead class="text-left text-xs text-ink-400"><tr><th class="py-1">Severity</th><th>Alert</th><th>Target ack / resolve</th><th>MTTD</th><th>MTTA</th><th>MTTR</th><th>SLA ack</th><th>SLA resolve</th></tr></thead>
            <tbody>
              <tr v-for="s in data.by_severity" :key="s.severity" class="border-t border-ink-800" :data-sev="s.severity">
                <td class="py-1.5"><CrBadge :tone="SEV_TONE[s.severity]">{{ s.severity }}</CrBadge></td>
                <td>{{ s.alerts }}</td>
                <td class="text-xs text-ink-400">{{ mins(s.target.ack_min) }} / {{ mins(s.target.resolve_min) }}</td>
                <td :title="`median ${dur(s.mttd.median_s)} · p90 ${dur(s.mttd.p90_s)}`">{{ dur(s.mttd.mean_s) }}</td>
                <td :title="`median ${dur(s.mtta.median_s)} · p90 ${dur(s.mtta.p90_s)}`">{{ dur(s.mtta.mean_s) }}</td>
                <td :title="`median ${dur(s.mttr.median_s)} · p90 ${dur(s.mttr.p90_s)}`">{{ dur(s.mttr.mean_s) }}</td>
                <td :class="pctTone(s.ack_sla_pct)">{{ pct(s.ack_sla_pct) }}</td>
                <td :class="pctTone(s.resolve_sla_pct)">{{ pct(s.resolve_sla_pct) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="mt-2 text-[11px] text-ink-500">Arahkan kursor ke angka untuk melihat median dan p90. Alert yang masih di dalam batas waktunya belum dihitung ke persentase SLA. Target bisa diubah lewat CR_SLA_TARGETS.</p>
        <div class="mt-3 flex flex-wrap gap-4 text-xs text-ink-300" data-test="sla-incidents">
          <span>Insiden dibuka: <b class="text-ink-100">{{ data.incidents.opened }}</b></span>
          <span>Insiden ditutup: <b class="text-ink-100">{{ data.incidents.closed }}</b></span>
          <span>MTTR insiden: <b class="text-ink-100">{{ dur(data.incidents.mttr.mean_s) }}</b></span>
        </div>
      </CrPanel>
      <CrPanel :title="`Pelanggaran SLA aktif (${data.breaches_total})`" class="xl:col-span-2">
        <p v-if="!data.breaches.length" class="py-6 text-center text-sm text-ok" data-test="no-breaches">Tidak ada alert terbuka yang melewati batas waktu.</p>
        <ul v-else class="divide-y divide-ink-800" data-test="breaches">
          <li v-for="b in data.breaches" :key="b.alert_id" class="py-2" :data-alert="b.alert_id">
            <RouterLink :to="{ name: 'incident-response', query: { alert: b.alert_id } }" class="flex items-start gap-2 hover:text-accent-300">
              <CrBadge :tone="SEV_TONE[b.severity]">{{ b.severity }}</CrBadge>
              <span class="flex-1 text-sm text-ink-100">{{ b.title }} <CrBadge v-if="b.is_demo">DEMO</CrBadge></span>
            </RouterLink>
            <div class="mt-0.5 pl-1 text-xs text-ink-400">
              {{ b.kind === 'ack' ? 'Belum di-acknowledge' : 'Belum selesai' }}, terlambat <b class="text-sev-critical">{{ dur(b.overdue_s) }}</b>
              · batas {{ fmtTime(b.deadline) }} · {{ b.assignee ? `ditangani ${b.assignee}` : 'belum ada yang menangani' }}
            </div>
          </li>
        </ul>
      </CrPanel>
    </div>
  </template>
</template>
