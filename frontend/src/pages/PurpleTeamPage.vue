<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { Download } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { ago } from '@/services/format'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const ui = useUiStore()
const data = ref(null)
const err = ref(null)
const days = ref(30)
async function load() { try { data.value = await api('/redteam/purple', { query: { days: days.value } }); err.value = null } catch (e) { err.value = e } }
onMounted(load)
watch(days, load)
const VERDICT = { detected: ['terdeteksi', 'ok'], partial: ['sebagian', 'warn'], missed: ['tidak terdeteksi', 'bad'] }
const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0)
const rate = computed(() => (data.value ? pct(data.value.detected_steps, data.value.attacked_steps) : 0))
async function dl() { try { await download('/redteam/purple/report', { days: days.value }, `purple-team-${days.value}d.md`) } catch (e) { ui.error(e) } }
</script>

<template>
  <PageHeader section="Red Team Operations" title="Purple Team: Diserang vs Terdeteksi" subtitle="Setiap langkah assessment yang dijalankan dicocokkan dengan alert SOC dari alamat penyerang dalam jendela waktu langkah tersebut.">
    <select v-model.number="days" class="input w-32" aria-label="Periode"><option :value="7">7 hari</option><option :value="30">30 hari</option><option :value="90">90 hari</option><option :value="365">365 hari</option></select>
    <CrButton :disabled="!data?.attacked_steps" @click="dl"><Download class="size-4" /> Laporan (.md)</CrButton>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!data" kind="loading" />
  <CrState v-else-if="!data.assessments.length" kind="empty" title="Belum ada assessment yang dijalankan"
           message="Jalankan skenario purple team (RT-PURPLE-01 sampai 05) dari Simulasi Serangan. Hasilnya muncul di sini per teknik ATT&CK." />
  <template v-else>
    <div class="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Langkah dijalankan</div><div class="font-mono text-2xl text-ink-100">{{ data.attacked_steps }}</div></div>
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Terdeteksi (alert apa pun)</div><div class="font-mono text-2xl text-ink-100" data-test="detected-rate">{{ rate }}%</div></div>
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Oleh rule teknik yang sama</div><div class="font-mono text-2xl text-ink-100">{{ pct(data.detected_same_steps, data.attacked_steps) }}%</div></div>
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Assessment dianalisis</div><div class="font-mono text-2xl text-ink-100">{{ data.assessments.length }}</div></div>
    </div>
    <CrPanel title="Per teknik ATT&CK" :padded="false" class="mb-4">
      <table class="data-table" data-test="purple-techniques">
        <thead><tr><th>Teknik</th><th>Taktik</th><th>Diserang</th><th>Terdeteksi</th><th>Rule teknik sama</th><th>Bukti sensor</th><th>Rule yang memicu</th><th>Hasil</th></tr></thead>
        <tbody><tr v-for="t in data.techniques" :key="t.technique" :data-tech="t.technique">
          <td><span class="font-mono text-xs">{{ t.technique }}</span> {{ t.name }}</td><td class="text-xs">{{ t.tactic }}</td>
          <td class="font-mono">{{ t.attacked }}</td><td class="font-mono">{{ t.detected }} <span class="text-ink-500">({{ pct(t.detected, t.attacked) }}%)</span></td>
          <td class="font-mono">{{ t.detected_same }}</td><td class="font-mono">{{ t.sensor }}</td>
          <td class="font-mono text-[11px]">{{ t.rules.join(', ') || '—' }}</td>
          <td><CrBadge :tone="VERDICT[t.verdict][1]">{{ VERDICT[t.verdict][0] }}</CrBadge></td>
        </tr></tbody>
      </table>
      <p class="border-t border-ink-700/60 p-3 text-xs text-ink-500">"Bukti sensor" menghitung deteksi yang didukung event Zeek/Suricata/Wazuh/syslog. Deteksi yang hanya berasal dari catatan aktivitas platform
        (dataset <code>redteam.activity</code>) membuktikan rule bekerja, tetapi belum membuktikan sensor jaringan melihat serangan. Pasang sensor lab untuk bukti penuh.</p>
    </CrPanel>
    <CrPanel title="Assessment" :padded="false">
      <table class="data-table">
        <thead><tr><th>Assessment</th><th>Skenario</th><th>Lab</th><th>Langkah</th><th>Terdeteksi</th><th>Dijalankan</th></tr></thead>
        <tbody><tr v-for="a in data.assessments" :key="a.id">
          <td><RouterLink :to="{ name: 'assessment', params: { id: a.id } }" class="text-accent-300 hover:underline">#{{ a.id }} {{ a.title }}</RouterLink> <CrBadge>{{ $st(a.status) }}</CrBadge></td>
          <td class="font-mono text-xs">{{ a.scenario }}</td><td class="text-xs">{{ a.lab }}</td><td class="font-mono">{{ a.steps }}</td>
          <td class="font-mono">{{ a.detected }}/{{ a.steps }}</td><td class="text-xs">{{ ago(a.started_at) }}</td>
        </tr></tbody>
      </table>
    </CrPanel>
  </template>
</template>
