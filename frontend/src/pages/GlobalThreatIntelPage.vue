<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import EChart from '@/components/charts/EChart.vue'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrKpi from '@/components/ui/CrKpi.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const router = useRouter()
const auth = useAuthStore()
const days = ref(7)
const demo = ref(true)
const data = ref(null)
const err = ref(null)
const loading = ref(false)
async function load() {
  loading.value = true
  try { data.value = await api('/intel/overview', { query: { days: days.value, include_demo: demo.value } }); err.value = null } catch (e) { err.value = e } finally { loading.value = false }
}
onMounted(load)
watch([days, demo], load)
const axis = { axisLine: { lineStyle: { color: '#22395a' } }, axisLabel: { color: '#6b84a6', fontSize: 10 } }
const tooltip = { trigger: 'axis', backgroundColor: '#0b1626', borderColor: '#22395a', textStyle: { color: '#c9d6e8' } }
const timeline = computed(() => {
  const s = data.value?.sightings
  if (!s) return {}
  return { backgroundColor: 'transparent', tooltip, grid: { left: 32, right: 8, top: 12, bottom: 24 },
    xAxis: { type: 'category', data: s.labels.map((l) => l.slice(5)), ...axis },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#162a45' } }, axisLabel: { color: '#6b84a6', fontSize: 10 } },
    series: [{ name: 'Sightings', type: 'bar', data: s.counts, itemStyle: { color: '#a78bfa' }, barMaxWidth: 22 }] }
})
const byType = computed(() => {
  const t = data.value?.active_by_type
  if (!t) return {}
  const entries = Object.entries(t).filter(([, v]) => v)
  return { backgroundColor: 'transparent', tooltip: { ...tooltip, trigger: 'item' },
    series: [{ type: 'pie', radius: ['45%', '72%'], label: { color: '#9bb0cc', fontSize: 11 }, data: entries.map(([name, value]) => ({ name, value })),
      color: ['#22d3ee', '#a78bfa', '#3b82f6', '#34d399', '#fbbf24', '#fb923c', '#f43f5e', '#94a3b8'] }] }
})
</script>

<template>
  <PageHeader section="Command Center" title="Threat Intelligence Global" subtitle="Titik temu indikator berbahaya dengan telemetri Anda: sighting dari waktu ke waktu, per sumber dan per field.">
    <select v-model.number="days" class="input w-32" aria-label="Jendela waktu"><option :value="1">24 jam terakhir</option><option :value="7">7 hari terakhir</option><option :value="30">30 hari terakhir</option></select>
    <label class="flex items-center gap-1.5 text-xs text-ink-300"><input v-model="demo" type="checkbox" class="accent-cyan-400" /> sertakan DEMO</label>
    <CrButton size="sm" :loading="loading" @click="load"><RefreshCw class="size-3.5" /> Muat ulang</CrButton>
  </PageHeader>
  <div v-if="err && !data" class="panel"><CrState kind="error" :message="err.message" @retry="load" /></div>
  <div v-else-if="!data" class="panel"><CrState kind="loading" /></div>
  <template v-else>
    <div class="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4" data-test="gti-kpis">
      <CrKpi label="Indikator aktif" :value="data.active_total" :to="{ name: 'threat-intel' }" />
      <CrKpi label="Sightings" :value="data.sightings.total" :tone="data.sightings.total ? 'warn' : 'ok'" :hint="`last ${days} day(s)`" :to="{ name: 'threat-intel', query: {} }" />
      <CrKpi label="Sumber" :value="data.sources.length" :hint="data.sources.filter((s) => s.is_demo).length ? 'includes DEMO feed' : undefined" />
      <CrKpi label="Indikator terlihat" :value="data.top_sighted.length" hint="distinct, top 10 shown below" />
    </div>
    <div class="grid gap-4 xl:grid-cols-3">
      <CrPanel title="Sighting per hari" class="xl:col-span-2">
        <CrState v-if="!data.sightings.total" kind="empty" message="Tidak ada indikator yang terlihat di telemetri tersimpan dalam jendela waktu ini." />
        <EChart v-else :option="timeline" height="240px" />
      </CrPanel>
      <CrPanel title="Indikator aktif per tipe">
        <CrState v-if="!data.active_total" kind="empty" :message="auth.can('intel.manage') ? 'Belum ada indikator. Tambahkan atau impor di Threat Intelligence.' : 'Belum ada indikator.'" />
        <EChart v-else :option="byType" height="240px" />
      </CrPanel>
      <CrPanel title="Indikator paling sering terlihat" class="xl:col-span-2" :padded="false">
        <CrState v-if="!data.top_sighted.length" kind="empty" />
        <table v-else class="data-table" data-test="top-sighted"><thead><tr><th>Indikator</th><th>Sumber</th><th>Severity</th><th>Sightings ({{ days }}d)</th><th>Terakhir</th></tr></thead>
          <tbody><tr v-for="i in data.top_sighted" :key="i.id" class="cursor-pointer" @click="router.push({ name: 'threat-intel', query: { id: i.id } })">
            <td><CrBadge>{{ i.type }}</CrBadge> <span class="font-mono text-xs text-ink-100">{{ i.value }}</span> <DemoTag v-if="i.is_demo" /></td><td class="text-xs">{{ i.source }}</td>
            <td><SevBadge :sev="i.severity" /></td><td class="font-mono text-xs text-warn">{{ i.window_sightings }}</td><td class="font-mono text-[11px] text-ink-400">{{ ago(i.last_sighted_at) }}</td></tr></tbody></table>
      </CrPanel>
      <CrPanel title="Lokasi kecocokan">
        <ul class="space-y-1 text-xs">
          <li v-for="(n, f) in data.sightings_by_field" :key="f" class="flex justify-between"><span class="font-mono text-ink-300">{{ f }}</span><span>{{ n }}</span></li>
          <li v-if="!Object.keys(data.sightings_by_field).length" class="text-ink-500">Belum ada sighting.</li>
        </ul>
        <div class="mt-4 mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-400">Per sumber</div>
        <ul class="space-y-1 text-xs"><li v-for="s in data.sightings_by_source" :key="s.source" class="flex justify-between"><span class="text-ink-300">{{ s.source }}</span><span>{{ s.count }}</span></li></ul>
      </CrPanel>
      <CrPanel title="Sighting terbaru" class="xl:col-span-2" :padded="false">
        <CrState v-if="!data.recent_sightings.length" kind="empty" />
        <table v-else class="data-table" data-test="recent-sightings"><thead><tr><th>Kapan</th><th>Indikator</th><th>Cocok di</th><th>Event</th></tr></thead>
          <tbody><tr v-for="s in data.recent_sightings" :key="s.id" class="cursor-pointer" @click="router.push({ name: 'threat-intel', query: { id: s.indicator.id } })">
            <td class="font-mono text-[11px]">{{ fmtTime(s.seen_at) }}</td><td><span class="font-mono text-xs">{{ s.indicator.value }}</span> <DemoTag v-if="s.is_demo" /></td><td><CrBadge>{{ s.field }}</CrBadge></td>
            <td class="max-w-md truncate text-xs text-ink-400">{{ s.event.dataset }} · {{ s.event.message }}</td></tr></tbody></table>
      </CrPanel>
      <CrPanel title="Sumber" :padded="false">
        <ul class="divide-y divide-ink-800 text-xs"><li v-for="s in data.sources" :key="s.id" class="px-4 py-2"><div class="flex justify-between"><b class="text-ink-200">{{ s.name }}</b><DemoTag v-if="s.is_demo" /></div>
          <div class="text-ink-500">{{ s.kind }} · {{ s.indicators_total }} indicators · {{ s.last_import_at ? `updated ${ago(s.last_import_at)}` : 'no imports' }}</div></li></ul>
      </CrPanel>
    </div>
    <p class="mt-3 text-[11px] text-ink-500">Peta serangan geografis memerlukan database geolokasi IP yang tidak disertakan; tampilan ini hanya menunjukkan apa yang dapat diverifikasi platform dari data Anda sendiri.</p>
  </template>
</template>
