<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { api } from '@/services/api'
import { localInput } from './rt'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'

const props = defineProps({ open: Boolean, scenarioId: Number })
const emit = defineEmits(['close', 'created'])
const scenarios = ref([])
const labs = ref([])
const errors = ref([])
const busy = ref(false)
const f = reactive({ title: '', justification: '', scenario_id: null, lab_id: null, attacker_node: '', target_nodes: [], start: '', end: '' })
watch(() => props.open, async (o) => {
  if (!o) return
  errors.value = []
  const now = new Date()
  Object.assign(f, { title: '', justification: '', target_nodes: [], attacker_node: '', start: localInput(now), end: localInput(new Date(now.getTime() + 4 * 3600e3)) })
  try { [scenarios.value, labs.value] = await Promise.all([api('/redteam/scenarios'), api('/redteam/labs')]) } catch (e) { errors.value = [e.message] }
  f.scenario_id = props.scenarioId || scenarios.value[0]?.id || null
  f.lab_id = labs.value[0]?.id || null
}, { immediate: true }) // also when the modal mounts already open (deep link ?scenario=)
const lab = computed(() => labs.value.find((l) => l.id === f.lab_id))
const scenario = computed(() => scenarios.value.find((s) => s.id === f.scenario_id))
watch(() => f.lab_id, () => { f.attacker_node = ''; f.target_nodes = [] })
watch(() => f.attacker_node, (a) => { f.target_nodes = f.target_nodes.filter((t) => t !== a) })
const ready = computed(() => f.title.trim().length >= 3 && f.justification.trim().length >= 10 && f.scenario_id && f.lab_id && f.attacker_node && f.target_nodes.length)
async function submit() {
  busy.value = true; errors.value = []
  try {
    const a = await api('/redteam/assessments', { method: 'POST', body: {
      title: f.title, justification: f.justification, scenario_id: f.scenario_id, lab_id: f.lab_id, attacker_node: f.attacker_node,
      target_nodes: f.target_nodes, window_start: new Date(f.start).toISOString(), window_end: new Date(f.end).toISOString() } })
    emit('created', a)
  } catch (e) { errors.value = Array.isArray(e.details) ? e.details.map((d) => (typeof d === 'string' ? d : d.msg)) : [e.message] } finally { busy.value = false }
}
const ips = (n) => Object.values(n.addresses).join(', ')
</script>

<template>
  <CrModal :open="open" title="Ajukan assessment terotorisasi" width="max-w-3xl" @close="emit('close')">
    <div class="space-y-3">
      <p class="rounded border border-sev-high/40 bg-sev-high/5 p-2 text-xs text-ink-300">Assessment hanya berjalan di dalam lab Anda sendiri yang sedang aktif, dari node lab, terhadap node lab yang Anda pilih, dalam jendela waktu yang disetujui. Orang kedua dengan hak persetujuan harus menyetujui sebelum apa pun dijalankan. Setiap langkah diaudit dan dicerminkan ke SIEM.</p>
      <div v-if="!labs.length" class="rounded border border-ink-700 p-3 text-sm text-ink-400">Anda tidak memiliki lab yang berjalan. Deploy satu di <RouterLink :to="{ name: 'labs' }" class="text-accent-300 hover:underline">Lab Manager</RouterLink> terlebih dahulu.</div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="field-label" for="ra-title">Judul</label><input id="ra-title" v-model="f.title" class="input" maxlength="255" /></div>
        <div><label class="field-label" for="ra-sc">Skenario</label><select id="ra-sc" v-model="f.scenario_id" class="input"><option v-for="s in scenarios" :key="s.id" :value="s.id">{{ s.code }} · {{ s.name }}</option></select></div>
      </div>
      <p v-if="scenario" class="text-xs text-ink-500">{{ scenario.objective }} Steps: {{ scenario.steps.map((s) => s.title).join(' → ') }}</p>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="field-label" for="ra-lab">Lab (berjalan)</label><select id="ra-lab" v-model="f.lab_id" class="input"><option v-for="l in labs" :key="l.id" :value="l.id">{{ l.name }} · {{ l.runtime_id }}</option></select></div>
        <div><label class="field-label" for="ra-att">Node penyerang (pijakan di dalam lab)</label>
          <select id="ra-att" v-model="f.attacker_node" class="input"><option value="" disabled>Pilih…</option><option v-for="n in lab?.nodes || []" :key="n.node_key" :value="n.node_key">{{ n.label }} · {{ ips(n) }}</option></select></div>
      </div>
      <div v-if="lab"><div class="field-label">Target</div>
        <div class="grid max-h-44 grid-cols-2 gap-1 overflow-y-auto rounded border border-ink-700 p-2">
          <label v-for="n in lab.nodes.filter((x) => x.node_key !== f.attacker_node)" :key="n.node_key" class="flex items-center gap-2 text-sm" :data-target="n.node_key">
            <input v-model="f.target_nodes" type="checkbox" :value="n.node_key" class="accent-cyan-400" />{{ n.label }} <span class="font-mono text-[11px] text-ink-500">{{ ips(n) }}</span></label>
        </div></div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="field-label" for="ra-start">Awal jendela</label><input id="ra-start" v-model="f.start" type="datetime-local" class="input" /></div>
        <div><label class="field-label" for="ra-end">Akhir jendela (maks 72 jam)</label><input id="ra-end" v-model="f.end" type="datetime-local" class="input" /></div>
      </div>
      <div><label class="field-label" for="ra-just">Justifikasi</label><textarea id="ra-just" v-model="f.justification" class="input" rows="2" placeholder="Mengapa assessment ini, apa yang harus dibuktikan" /></div>
      <ul v-if="errors.length" class="rounded border border-sev-critical/40 bg-sev-critical/5 p-2 text-xs text-sev-critical" role="alert"><li v-for="(e, i) in errors" :key="i">{{ e }}</li></ul>
    </div>
    <template #footer><CrButton @click="emit('close')">Batal</CrButton><CrButton variant="primary" :disabled="!ready" :loading="busy" @click="submit">Ajukan untuk persetujuan</CrButton></template>
  </CrModal>
</template>
