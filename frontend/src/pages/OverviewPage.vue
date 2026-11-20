<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Activity, AlertOctagon, Ban, Boxes, KeyRound, RefreshCw, ShieldAlert, ShieldX, Siren, Network, Server, Play, Container, Crosshair, Radar, Antenna, Bell, Bug, FolderOpen, Flag, Target } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, outcomeTone } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import EChart from '@/components/charts/EChart.vue'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrKpi from '@/components/ui/CrKpi.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import StatusDot from '@/components/ui/StatusDot.vue'

const auth = useAuthStore()
const ui = useUiStore()
const router = useRouter()
const range = ref(localStorage.getItem('cr.overview.range') || '24h')
const data = ref(null)
const loading = ref(true)
const err = ref(null)
let timer

async function load(silent = false) {
  if (!silent) loading.value = true
  err.value = null
  try { data.value = await api('/dashboard/overview', { query: { range: range.value } }) }
  catch (e) { err.value = e; if (silent) ui.error(e) }
  finally { loading.value = false }
}
watch(range, (r) => { localStorage.setItem('cr.overview.range', r); load() })
onMounted(() => { load(); timer = setInterval(() => load(true), 30000) })
onBeforeUnmount(() => clearInterval(timer))

const auditTo = (q) => (auth.can('audit.view') ? { name: 'audit', query: q } : undefined)
const k = computed(() => data.value?.kpis || {})
const soc = computed(() => auth.can('blueteam.alerts.view'))

const activityOption = computed(() => {
  const a = data.value?.activity
  if (!a) return {}
  const labels = a.labels.map((l) => (a.bucket === 'hour' ? l.slice(11) : l.slice(5)))
  const s = (name, key, color) => ({ name, type: 'bar', stack: 't', data: a.series[key], itemStyle: { color }, barMaxWidth: 18, emphasis: { focus: 'series' } })
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'axis', backgroundColor: '#0b1626', borderColor: '#22395a', textStyle: { color: '#c9d6e8' } },
    legend: { top: 0, right: 0, textStyle: { color: '#9bb0cc' }, itemWidth: 10, itemHeight: 10 },
    grid: { left: 36, right: 8, top: 32, bottom: 24 },
    xAxis: { type: 'category', data: labels, axisLine: { lineStyle: { color: '#22395a' } }, axisLabel: { color: '#6b84a6', fontSize: 10 } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#162a45' } }, axisLabel: { color: '#6b84a6', fontSize: 10 } },
    series: [s('Success', 'success', '#22d3ee'), s('Failure', 'failure', '#fb923c'), s('Denied', 'denied', '#f43f5e')],
  }
})
const actionsOption = computed(() => {
  const t = data.value?.top_actions || []
  const pal = ['#22d3ee', '#3b82f6', '#a78bfa', '#34d399', '#fb923c', '#facc15', '#f43f5e', '#94a3b8']
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', backgroundColor: '#0b1626', borderColor: '#22395a', textStyle: { color: '#c9d6e8' } },
    series: [{ type: 'pie', radius: ['55%', '80%'], itemStyle: { borderColor: '#08111f', borderWidth: 2 }, label: { show: false },
      data: t.map((x, i) => ({ name: x.action, value: x.count, itemStyle: { color: pal[i % pal.length] } })) }],
  }
})
function onActionSelect(p) { if (auth.can('audit.view') && p?.name) router.push({ name: 'audit', query: { action: p.name } }) }
</script>

<template>
  <PageHeader section="Command Center" title="Dashboard Overview" subtitle="Angka langsung dari MySQL: telemetri SOC, threat intelligence, lab dan jejak audit platform. Data DEMO tidak disertakan.">
    <div class="flex rounded-md border border-ink-700 p-0.5" role="group" aria-label="Rentang waktu">
      <button v-for="r in ['24h', '7d', '30d']" :key="r" :class="['rounded px-3 py-1 font-mono text-xs', range === r ? 'bg-accent-500/15 text-accent-300' : 'text-ink-400 hover:text-ink-100']" @click="range = r">{{ r }}</button>
    </div>
    <CrButton size="sm" :loading="loading" @click="load()"><RefreshCw class="size-3.5" /> Muat ulang</CrButton>
  </PageHeader>

  <div v-if="err && !data" class="panel"><CrState kind="error" :message="err.message" @retry="load()" /></div>
  <div v-else-if="loading && !data" class="panel"><CrState kind="loading" /></div>
  <template v-else-if="data">
    <div class="mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-ink-500">Telemetri keamanan</div>
    <div class="mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
      <CrKpi label="Total Alert" :value="k.total_alerts" :icon="AlertOctagon" :hint="`${k.open_alerts} terbuka · tanpa DEMO`" :to="soc ? { name: 'incident-response' } : undefined" />
      <CrKpi label="Alert Kritis" :value="k.critical_alerts" :icon="ShieldAlert" :tone="k.critical_alerts ? 'bad' : 'ok'" :to="soc ? { name: 'incident-response', query: { severity: 4 } } : undefined" />
      <CrKpi label="Insiden Terbuka" :value="k.open_incidents" :icon="Siren" :tone="k.open_incidents ? 'warn' : 'ok'" :to="auth.can('incident.view') ? { name: 'incident-response', query: { tab: 'incidents' } } : undefined" />
      <CrKpi label="Aset Dipantau" :value="k.assets_monitored" :icon="Boxes" hint="IP dan host internal yang terlihat di telemetri" />
      <CrKpi label="Ancaman Diblokir" :value="k.threats_blocked" :icon="ShieldX" tone="ok" :to="soc ? { name: 'siem', query: { q: 'action:blocked' } } : undefined" />
    </div>
    <div class="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4" data-test="intel-kpis">
      <CrKpi label="Indikator Aktif" :value="k.intel_active_indicators" :icon="Crosshair" hint="threat intel, tanpa DEMO" :to="auth.can('intel.view') ? { name: 'threat-intel' } : undefined" />
      <CrKpi label="Sighting Indikator" :value="k.intel_sightings" :icon="Radar" :tone="k.intel_sightings ? 'warn' : 'ok'" :hint="`dalam ${data.range} terakhir`" :to="auth.can('intel.view') ? { name: 'threat-intel-global' } : undefined" />
      <CrKpi label="Sumber Sensor" :value="k.sensor_sources" :icon="Antenna" :hint="`${k.sensor_sources_active} event terkirim dalam satu jam terakhir`" :to="soc ? { name: 'siem', query: { tab: 'sources' } } : undefined" />
      <CrKpi label="Alert Terbuka" :value="k.open_alerts" :icon="Bell" :tone="k.open_alerts ? 'warn' : 'ok'" :to="soc ? { name: 'incident-response' } : undefined" />
    </div>
    <div class="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4" data-test="phase7-kpis">
      <CrKpi label="Kerentanan Terbuka" :value="k.vuln_open" :icon="ShieldAlert" :tone="k.vuln_open_critical ? 'bad' : k.vuln_open ? 'warn' : 'ok'" :hint="`${k.vuln_open_critical} kritis · ${k.vuln_open_high} tinggi · ${k.remediation_overdue} tugas lewat tenggat`" :to="auth.can('vuln.view') ? { name: 'vulnerabilities' } : undefined" />
      <CrKpi label="Sampel Dianalisis" :value="k.samples_total" :icon="Bug" :hint="`${k.samples_yara_hits} dengan hit YARA · ${k.samples_malicious} berbahaya (analis)`" :to="auth.can('malware.view') ? { name: 'malware' } : undefined" />
      <CrKpi label="Kasus Terbuka" :value="k.cases_open" :icon="FolderOpen" :hint="`${k.evidence_total} item evidence`" :to="auth.can('evidence.view') ? { name: 'cases' } : undefined" />
      <CrKpi label="Integritas Tidak Cocok" :value="k.evidence_integrity_mismatch" :icon="ShieldX" :tone="k.evidence_integrity_mismatch ? 'bad' : 'ok'" hint="evidence yang isinya tidak lagi cocok" :to="auth.can('evidence.view') ? { name: 'forensics' } : undefined" />
    </div>
    <div class="mb-5 grid grid-cols-2 gap-3" data-test="phase8-kpis">
      <CrKpi label="CTF Challenges" :value="k.challenges_published" :icon="Flag" :hint="`${k.ctf_solves} solve`" :to="auth.can('training.participate|training.manage') ? { name: 'ctf' } : undefined" />
      <CrKpi label="Misi" :value="k.missions_published" :icon="Target" hint="terbit" :to="auth.can('training.participate|training.manage') ? { name: 'missions' } : undefined" />
    </div>
    <div class="mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-ink-500">Platform · last {{ data.range }}</div>
    <div class="mb-5 grid grid-cols-3 gap-3">
      <CrKpi label="Sesi Aktif" :value="k.active_sessions" :icon="KeyRound" />
      <CrKpi label="Akses Ditolak" :value="k.access_denied" :icon="Ban" :tone="k.access_denied ? 'bad' : 'accent'" :to="auditTo({ outcome: 'denied' })" />
      <CrKpi label="Event Audit" :value="k.audit_events" :icon="Activity" :to="auditTo({})" />
    </div>
    <div class="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4" data-test="lab-kpis">
      <CrKpi label="Topologi Jaringan" :value="k.topology_networks" :icon="Network" :to="auth.can('lab.view') ? { name: 'networks' } : undefined" />
      <CrKpi label="Labs" :value="k.labs" :icon="Server" :to="auth.can('lab.view') ? { name: 'labs' } : undefined" />
      <CrKpi label="Lab Berjalan" :value="k.labs_running" :icon="Play" tone="ok" :to="auth.can('lab.view') ? { name: 'labs' } : undefined" />
      <CrKpi label="Container Lab Aktif" :value="k.lab_containers" :icon="Container" />
    </div>

    <div class="grid gap-4 xl:grid-cols-3">
      <CrPanel title="Aktivitas platform" class="xl:col-span-2"><EChart :option="activityOption" height="260px" /></CrPanel>
      <CrPanel title="Aksi teratas">
        <CrState v-if="!data.top_actions.length" kind="empty" message="Tidak ada aktivitas dalam rentang ini." />
        <template v-else>
          <EChart :option="actionsOption" height="170px" @select="onActionSelect" />
          <ul class="mt-2 space-y-1 text-xs">
            <li v-for="a in data.top_actions" :key="a.action" class="flex justify-between font-mono"><span class="truncate text-ink-300">{{ a.action }}</span><span class="text-ink-400">{{ a.count }}</span></li>
          </ul>
        </template>
      </CrPanel>

      <CrPanel title="Aktivitas terbaru" class="xl:col-span-2" :padded="false">
        <CrState v-if="data.recent_activity === null" kind="denied" message="Feed aktivitas terlihat oleh role dengan akses audit." :missing="['audit.view']" />
        <CrState v-else-if="!data.recent_activity.length" kind="empty" />
        <table v-else class="data-table">
          <thead><tr><th>Kapan</th><th>Aktor</th><th>Aksi</th><th>Sumber daya</th><th>Hasil</th></tr></thead>
          <tbody>
            <tr v-for="r in data.recent_activity" :key="r.id" class="cursor-pointer" @click="router.push({ name: 'audit', query: { action: r.action } })">
              <td class="font-mono text-xs text-ink-400">{{ ago(r.occurred_at) }}</td>
              <td class="text-ink-100">{{ r.actor }}</td>
              <td class="font-mono text-xs">{{ r.action }}</td>
              <td class="font-mono text-xs text-ink-400">{{ r.resource_type ? `${r.resource_type}:${r.resource_id ?? ''}` : '—' }}</td>
              <td><CrBadge :tone="outcomeTone(r.outcome)">{{ r.outcome }}</CrBadge></td>
            </tr>
          </tbody>
        </table>
      </CrPanel>

      <CrPanel title="Status sistem">
        <ul class="space-y-3 text-sm">
          <li v-for="(s, name) in data.system_status" :key="name" class="flex items-center justify-between">
            <span class="flex items-center gap-2 capitalize text-ink-200"><StatusDot :status="s" /> {{ name }}</span>
            <CrBadge :tone="s === 'up' ? 'ok' : 'bad'">{{ s }}</CrBadge>
          </li>
          <li class="flex items-center justify-between"><span class="flex items-center gap-2 text-ink-200"><StatusDot :status="!k.sensor_sources ? 'unknown' : k.sensor_sources_active ? 'up' : 'degraded'" /> Sensors (Zeek/Suricata/Wazuh)</span>
            <CrBadge :tone="!k.sensor_sources ? 'neutral' : k.sensor_sources_active ? 'ok' : 'warn'" data-test="sensor-status">{{ !k.sensor_sources ? 'none registered' : `${k.sensor_sources_active}/${k.sensor_sources} active` }}</CrBadge></li>
        </ul>
        <RouterLink v-if="auth.can('system.health.view')" :to="{ name: 'system-health' }" class="mt-4 inline-block text-xs text-accent-400 hover:underline">Buka Kesehatan Sistem →</RouterLink>
      </CrPanel>
    </div>
  </template>
</template>
