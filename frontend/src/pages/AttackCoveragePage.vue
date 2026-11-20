<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { api } from '@/services/api'
import { useAuthStore } from '@/stores/auth'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const auth = useAuthStore()
const data = ref(null)
const err = ref(null)
const days = ref(30)
const mode = ref('coverage')
const onlyRelevant = ref(true)
const sel = ref(null)
async function load() { try { data.value = await api('/soc/attack/matrix', { query: { days: days.value } }); err.value = null } catch (e) { err.value = e } }
onMounted(load)
watch(days, load)

const canPurple = computed(() => auth.can('redteam.assessment.view'))
function relevant(c) { return c.rules.length || c.simulated_by.length || c.alerts || c.purple }
const tactics = computed(() => (data.value?.tactics || []).map((t) => ({ ...t, shown: onlyRelevant.value ? t.techniques.filter(relevant) : t.techniques })))

function cellClass(c) {
  if (mode.value === 'purple') {
    if (!c.purple) return 'border-ink-700 bg-ink-900 text-ink-500'
    return { detected: 'border-ok/60 bg-ok/15 text-ok', partial: 'border-warn/60 bg-warn/15 text-warn', missed: 'border-sev-critical/60 bg-sev-critical/15 text-sev-critical' }[c.purple.verdict]
  }
  if (c.enabled_rules) return 'border-ok/50 bg-ok/10 text-ink-100'
  if (c.covered) return 'border-ok/30 bg-ok/5 text-ink-200'
  if (c.rules.length) return 'border-warn/40 bg-warn/5 text-ink-200'
  return 'border-ink-700 bg-ink-900 text-ink-400'
}
const VERDICT = { detected: 'terdeteksi', partial: 'sebagian', missed: 'tidak terdeteksi' }
const ORIGIN = { builtin: 'bawaan', sigma: 'Sigma', manual: 'manual' }
</script>

<template>
  <PageHeader section="Blue Team Operations" title="Matriks MITRE ATT&CK" subtitle="Cakupan deteksi per teknik: rule aktif, alert, aksi red team yang dapat mensimulasikannya, dan hasil purple team.">
    <select v-model.number="days" class="input w-32" aria-label="Periode"><option :value="7">7 hari</option><option :value="30">30 hari</option><option :value="90">90 hari</option></select>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!data" kind="loading" />
  <template v-else>
    <div class="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Teknik tercakup rule aktif</div><div class="font-mono text-2xl text-ink-100" data-test="covered">{{ data.totals.covered }} <span class="text-sm text-ink-500">/ {{ data.totals.techniques }}</span></div></div>
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Rule terpetakan</div><div class="font-mono text-2xl text-ink-100">{{ data.totals.rules_mapped }} <span class="text-sm text-ink-500">/ {{ data.totals.rules }}</span></div></div>
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Teknik yang bisa disimulasikan</div><div class="font-mono text-2xl text-ink-100">{{ data.totals.simulated }}</div></div>
      <div class="panel p-3"><div class="text-[11px] uppercase text-ink-500">Sumber referensi</div><div class="text-xs text-ink-300">Subset ATT&amp;CK Enterprise (attack.mitre.org). Teknik lain tetap diterima pada rule.</div></div>
    </div>
    <div class="mb-3 flex flex-wrap items-center gap-3 text-sm">
      <div class="inline-flex overflow-hidden rounded-md border border-ink-600" role="tablist">
        <button :class="['px-3 py-1.5', mode === 'coverage' ? 'bg-accent-500/20 text-accent-200' : 'text-ink-300']" role="tab" @click="mode = 'coverage'">Cakupan rule</button>
        <button :class="['px-3 py-1.5', mode === 'purple' ? 'bg-accent-500/20 text-accent-200' : 'text-ink-300', !canPurple && 'cursor-not-allowed opacity-50']" role="tab" :disabled="!canPurple"
                :title="canPurple ? '' : 'memerlukan: redteam.assessment.view'" data-test="mode-purple" @click="mode = 'purple'">Diserang vs terdeteksi</button>
      </div>
      <label class="flex items-center gap-2"><input v-model="onlyRelevant" type="checkbox" /> Hanya teknik yang punya rule, alert atau simulasi</label>
      <div v-if="mode === 'coverage'" class="flex flex-wrap gap-2 text-[11px]"><span class="rounded border border-ok/50 bg-ok/10 px-1.5">rule aktif</span><span class="rounded border border-ok/30 bg-ok/5 px-1.5">tercakup oleh teknik induk</span><span class="rounded border border-warn/40 bg-warn/5 px-1.5">hanya rule nonaktif</span><span class="rounded border border-ink-700 px-1.5">belum ada rule</span></div>
      <div v-else class="flex flex-wrap gap-2 text-[11px]"><span class="rounded border border-ok/60 bg-ok/15 px-1.5">terdeteksi</span><span class="rounded border border-warn/60 bg-warn/15 px-1.5">sebagian</span><span class="rounded border border-sev-critical/60 bg-sev-critical/15 px-1.5">tidak terdeteksi</span><span class="rounded border border-ink-700 px-1.5">belum diuji</span>
        <RouterLink :to="{ name: 'purple-team' }" class="text-accent-300 underline">Laporan purple team</RouterLink></div>
    </div>
    <div class="overflow-x-auto pb-2">
      <div class="grid min-w-[1100px] gap-2" :style="{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0, 1fr))` }" data-test="matrix">
        <div v-for="t in tactics" :key="t.id" class="min-w-0">
          <div class="mb-2 rounded bg-ink-800 p-2 text-center"><div class="text-[11px] font-semibold leading-tight text-ink-100">{{ t.name }}</div>
            <div class="font-mono text-[10px] text-ink-500">{{ t.id }} · {{ t.covered }}/{{ t.total }}</div></div>
          <div class="space-y-1">
            <button v-for="c in t.shown" :key="c.id" :class="['block w-full rounded border p-1.5 text-left text-[10px] leading-tight hover:ring-1 hover:ring-accent-400', cellClass(c)]"
                    :data-tech="c.id" @click="sel = c">
              <div class="font-mono">{{ c.id }}</div><div class="line-clamp-2">{{ c.name }}</div>
              <div v-if="mode === 'coverage' && (c.enabled_rules || c.alerts)" class="mt-0.5 font-mono text-[9px] opacity-80">{{ c.enabled_rules }} rule · {{ c.alerts }} alert</div>
              <div v-if="mode === 'purple' && c.purple" class="mt-0.5 font-mono text-[9px]">{{ c.purple.detected }}/{{ c.purple.attacked }} terdeteksi</div>
            </button>
            <div v-if="!t.shown.length" class="rounded border border-dashed border-ink-700 p-2 text-center text-[10px] text-ink-500">—</div>
          </div>
        </div>
      </div>
    </div>
  </template>

  <CrModal :open="!!sel" :title="sel ? `${sel.id} ${sel.name}` : ''" width="max-w-2xl" @close="sel = null">
    <div v-if="sel" class="space-y-3 text-sm">
      <div class="flex flex-wrap gap-1.5"><CrBadge v-for="t in sel.tactics" :key="t">{{ t }}</CrBadge>
        <a :href="`https://attack.mitre.org/techniques/${sel.id.replace('.', '/')}/`" target="_blank" rel="noopener noreferrer" class="text-xs text-accent-300 underline">attack.mitre.org</a></div>
      <section><h3 class="field-label">Rule deteksi</h3>
        <ul v-if="sel.rules.length" class="space-y-1"><li v-for="r in sel.rules" :key="r.id" class="flex items-center gap-2"><CrBadge :tone="r.enabled ? 'ok' : 'neutral'">{{ r.enabled ? 'aktif' : 'nonaktif' }}</CrBadge><span class="font-mono text-xs">{{ r.code }}</span> {{ r.name }} <span class="text-[11px] text-ink-500">({{ ORIGIN[r.origin] || r.origin }})</span></li></ul>
        <p v-else class="text-xs text-ink-500">Belum ada rule. Buat rule baru atau impor rule Sigma untuk teknik ini di <RouterLink :to="{ name: 'detection-rules' }" class="text-accent-300 underline">Rule Deteksi</RouterLink>.</p></section>
      <section><h3 class="field-label">Alert ({{ data.days }} hari)</h3><p class="font-mono">{{ sel.alerts }}</p></section>
      <section><h3 class="field-label">Dapat disimulasikan oleh aksi red team</h3>
        <p v-if="sel.simulated_by.length" class="font-mono text-xs">{{ sel.simulated_by.join(', ') }}</p><p v-else class="text-xs text-ink-500">Tidak ada aksi aman di katalog untuk teknik ini.</p></section>
      <section v-if="sel.purple"><h3 class="field-label">Hasil purple team</h3>
        <p>Diserang {{ sel.purple.attacked }}× · terdeteksi {{ sel.purple.detected }}× · oleh rule teknik yang sama {{ sel.purple.detected_same }}× · bukti sensor {{ sel.purple.sensor }}× ·
          <b>{{ VERDICT[sel.purple.verdict] }}</b></p></section>
    </div>
  </CrModal>
</template>
