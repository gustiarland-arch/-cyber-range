<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { AlertOctagon, Ban, FileSearch, ShieldCheck, Siren, Timer } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago } from '@/services/format'
import { SEVERITIES, SEV_COLOR, sevName } from '@/services/soc'
import EChart from '@/components/charts/EChart.vue'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrKpi from '@/components/ui/CrKpi.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const router = useRouter()
const o = ref(null)
const err = ref(null)
const demo = ref(true)
async function load() { try { o.value = await api('/soc/overview', { query: { include_demo: demo.value } }); err.value = null } catch (e) { err.value = e } }
onMounted(load)
const axis = { axisLabel: { color: '#6b84a6', fontSize: 10 }, axisLine: { lineStyle: { color: '#22395a' } } }
const trend = computed(() => {
  if (!o.value) return {}
  const hours = [...new Set([...o.value.events_by_hour.map((x) => x.hour), ...o.value.alerts_by_hour.map((x) => x.hour)])].sort()
  const ev = Object.fromEntries(o.value.events_by_hour.map((x) => [x.hour, x.count]))
  const al = Object.fromEntries(o.value.alerts_by_hour.map((x) => [x.hour, x.count]))
  return {
    grid: { left: 40, right: 40, top: 24, bottom: 24 }, tooltip: { trigger: 'axis' }, legend: { textStyle: { color: '#93a7c4', fontSize: 11 }, top: 0 },
    xAxis: { type: 'category', data: hours.map((h) => h.slice(11)), ...axis },
    yAxis: [{ type: 'value', ...axis, splitLine: { lineStyle: { color: '#16263d' } } }, { type: 'value', minInterval: 1, ...axis, splitLine: { show: false } }],
    series: [{ name: 'events', type: 'line', smooth: true, areaStyle: { opacity: 0.12 }, itemStyle: { color: '#22d3ee' }, data: hours.map((h) => ev[h] || 0) },
      { name: 'new alerts', type: 'bar', yAxisIndex: 1, itemStyle: { color: '#fb923c' }, barMaxWidth: 10, data: hours.map((h) => al[h] || 0) }],
  }
})
const sevOption = computed(() => o.value && ({
  tooltip: {}, series: [{ type: 'pie', radius: ['55%', '80%'], label: { show: false }, itemStyle: { borderColor: '#08111f', borderWidth: 2 },
    data: SEVERITIES.map((s, i) => ({ name: s, value: o.value.open_alerts[s] || 0, itemStyle: { color: SEV_COLOR[i] } })).filter((d) => d.value) }],
}))
const fmtDur = (s) => (s == null ? '—' : s < 120 ? `${Math.round(s)}s` : s < 7200 ? `${Math.round(s / 60)}m` : `${(s / 3600).toFixed(1)}h`)
const sourceHealth = (s) => (!s.is_enabled ? ['neutral', 'disabled'] : !s.last_event_at ? ['neutral', 'no data'] : (Date.now() - new Date(`${s.last_event_at}Z`)) > 3600e3 ? ['warn', 'silent >1h'] : ['ok', 'receiving'])
</script>

<template>
  <PageHeader section="Blue Team Operations" title="Defense Center" subtitle="Postur SOC dalam 24 jam terakhir: beban alert, cakupan deteksi dan kesehatan sensor.">
    <label class="flex items-center gap-1.5 text-xs text-ink-300"><input v-model="demo" type="checkbox" class="accent-cyan-400" @change="load" /> sertakan data DEMO</label>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!o" kind="loading" />
  <template v-else>
    <div class="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6" data-test="soc-kpis">
      <CrKpi label="Alert terbuka" :value="o.open_alerts_total" :icon="AlertOctagon" :tone="o.open_alerts_total ? 'warn' : 'ok'" :to="{ name: 'incident-response' }" />
      <CrKpi label="Kritis / tinggi" :value="(o.open_alerts.critical || 0) + (o.open_alerts.high || 0)" :icon="AlertOctagon" :tone="(o.open_alerts.critical || o.open_alerts.high) ? 'bad' : 'ok'" />
      <CrKpi label="Insiden aktif" :value="o.open_incidents" :icon="Siren" :to="{ name: 'incident-response', query: { tab: 'incidents' } }" />
      <CrKpi label="Event 24 jam" :value="o.events_24h.toLocaleString()" :icon="FileSearch" :to="{ name: 'siem' }" />
      <CrKpi label="Diblokir 24 jam" :value="o.blocked_24h" :icon="Ban" tone="ok" :to="{ name: 'siem', query: { q: 'action:blocked' } }" />
      <CrKpi label="Rata-rata waktu respons" :value="fmtDur(o.mean_time_to_ack_s)" :icon="Timer" hint="30 hari terakhir" />
    </div>
    <div class="mb-4 grid gap-4 xl:grid-cols-3">
      <CrPanel title="Event dan alert per jam" class="xl:col-span-2">
        <CrState v-if="!o.events_by_hour.length" kind="empty" message="Tidak ada event dalam 24 jam terakhir." />
        <EChart v-else :option="trend" height="230px" />
      </CrPanel>
      <CrPanel title="Alert terbuka per severity">
        <CrState v-if="!o.open_alerts_total" kind="empty" message="Tidak ada alert terbuka." />
        <template v-else><EChart :option="sevOption" height="160px" />
          <div class="mt-2 flex flex-wrap justify-center gap-2"><span v-for="(n, s) in o.open_alerts" :key="s" class="font-mono text-xs"><SevBadge :sev="SEVERITIES.indexOf(s)" /> {{ n }}</span></div></template>
      </CrPanel>
    </div>
    <div class="grid gap-4 xl:grid-cols-3">
      <CrPanel title="Cakupan deteksi (MITRE ATT&CK)" :padded="false">
        <table class="data-table"><thead><tr><th>Taktik</th><th>Rules</th><th>Teknik</th></tr></thead>
          <tbody><tr v-for="c in o.coverage" :key="c.tactic"><td class="text-ink-100">{{ c.tactic }}</td><td class="font-mono text-xs">{{ c.enabled }}/{{ c.rules }}</td>
            <td class="font-mono text-[11px] text-ink-400">{{ c.techniques.join(' ') }}</td></tr></tbody></table>
        <div class="px-4 py-2 text-[11px] text-ink-500"><RouterLink :to="{ name: 'detection-rules' }" class="text-accent-300 hover:underline">Kelola rule</RouterLink> · aktif/total</div>
      </CrPanel>
      <CrPanel title="Sumber aktivitas mencurigakan teratas" subtitle="IP sumber event medium+, 24 jam" :padded="false">
        <CrState v-if="!o.top_attackers.length" kind="empty" message="Tidak ada dalam 24 jam terakhir." />
        <button v-for="a in o.top_attackers" :key="a.ip" class="flex w-full items-center gap-2 px-4 py-2 text-left hover:bg-ink-800" @click="router.push({ name: 'siem', query: { q: `src:${a.ip}` } })">
          <span class="font-mono text-xs text-ink-100">{{ a.ip }}</span><span class="ml-auto font-mono text-[11px] text-ink-400">{{ a.events }} event</span>
          <span class="size-2 rounded-full" :style="{ background: SEV_COLOR[a.max_severity] }" :title="`max ${sevName(a.max_severity)}`" /></button>
        <div v-if="o.top_rules.length" class="border-t border-ink-700/60 px-4 py-2">
          <div class="mb-1 text-[10px] uppercase tracking-wider text-ink-500">Rule paling aktif</div>
          <div v-for="r in o.top_rules" :key="r.code" class="flex justify-between text-xs"><span class="truncate">{{ r.name }}</span><span class="font-mono text-ink-400">{{ r.hits }}</span></div>
        </div>
      </CrPanel>
      <CrPanel title="Kesehatan sensor" :padded="false">
        <ul class="divide-y divide-ink-800" data-test="sensor-health">
          <li v-for="s in o.sources" :key="s.id" class="flex items-center gap-2 px-4 py-2">
            <ShieldCheck class="size-4 text-ink-500" />
            <div class="min-w-0 flex-1"><div class="truncate text-sm text-ink-100">{{ s.name }} <DemoTag v-if="s.is_demo" /></div>
              <div class="font-mono text-[11px] text-ink-500">{{ s.kind }} · {{ s.events_24h }} event 24 jam · terakhir {{ s.last_event_at ? ago(s.last_event_at) : 'never' }}</div></div>
            <CrBadge :tone="sourceHealth(s)[0]">{{ sourceHealth(s)[1] }}</CrBadge>
          </li>
        </ul>
        <div class="px-4 py-2 text-[11px]"><RouterLink :to="{ name: 'siem', query: { tab: 'sources' } }" class="text-accent-300 hover:underline">Kelola sumber log</RouterLink></div>
      </CrPanel>
    </div>
  </template>
</template>
