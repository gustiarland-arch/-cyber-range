<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { api } from '@/services/api'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'

const props = defineProps({ open: Boolean, meta: Object })
const emit = defineEmits(['close', 'started'])
const labs = ref(null)
const err = ref('')
const busy = ref(false)
const f = reactive({ name: '', lab_id: null, scanner_node: '', target_nodes: [], profile: 'standard', ports: '' })
watch(() => props.open, async (o) => {
  if (!o) return
  err.value = ''
  Object.assign(f, { name: `Scan ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`, scanner_node: '', target_nodes: [], profile: 'standard', ports: '' })
  try { labs.value = await api('/vuln/labs') } catch (e) { err.value = e.message; labs.value = [] }
  f.lab_id = labs.value[0]?.id || null
}, { immediate: true })
const lab = computed(() => labs.value?.find((l) => l.id === f.lab_id))
watch(() => f.lab_id, () => { f.scanner_node = ''; f.target_nodes = [] })
watch(() => f.scanner_node, (s) => { f.target_nodes = f.target_nodes.filter((t) => t !== s) })
const ports = computed(() => f.ports.split(/[\s,]+/).filter(Boolean).map(Number))
const ready = computed(() => f.name.trim().length >= 3 && f.lab_id && f.scanner_node && f.target_nodes.length && (f.profile !== 'custom' || (ports.value.length && ports.value.every((p) => p >= 1 && p <= 65535))))
const ips = (n) => Object.values(n.addresses).join(', ')
async function submit() {
  busy.value = true; err.value = ''
  try {
    const j = await api('/vuln/scans', { method: 'POST', body: { name: f.name, lab_id: f.lab_id, scanner_node: f.scanner_node, target_nodes: f.target_nodes, profile: f.profile, ports: f.profile === 'custom' ? ports.value : null } })
    emit('started', j)
  } catch (e) { err.value = Array.isArray(e.details) ? e.details.map((d) => d.msg || d).join('; ') : e.message } finally { busy.value = false }
}
</script>

<template>
  <CrModal :open="open" title="Scan kerentanan baru" width="max-w-3xl" @close="emit('close')">
    <div class="space-y-3 text-sm" data-test="new-scan">
      <p class="rounded border border-accent-500/30 bg-accent-500/5 p-2 text-xs text-ink-300">{{ meta?.policy }}</p>
      <div v-if="labs && !labs.length" class="rounded border border-ink-700 p-3 text-ink-400">Anda tidak memiliki lab yang berjalan. Deploy satu di <RouterLink :to="{ name: 'labs' }" class="text-accent-300 hover:underline">Lab Manager</RouterLink> terlebih dahulu.</div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="field-label" for="vs-name">Nama</label><input id="vs-name" v-model="f.name" class="input" maxlength="160" /></div>
        <div><label class="field-label" for="vs-lab">Lab (berjalan)</label><select id="vs-lab" v-model="f.lab_id" class="input"><option v-for="l in labs || []" :key="l.id" :value="l.id">{{ l.name }} · {{ l.runtime_id }}</option></select></div>
        <div><label class="field-label" for="vs-scanner">Node scanner (menjalankan pemeriksaan)</label>
          <select id="vs-scanner" v-model="f.scanner_node" class="input"><option value="" disabled>Pilih…</option><option v-for="n in lab?.nodes || []" :key="n.node_key" :value="n.node_key">{{ n.label }} · {{ ips(n) }}</option></select></div>
        <div><label class="field-label" for="vs-profile">Profil</label>
          <select id="vs-profile" v-model="f.profile" class="input"><option value="quick">quick ({{ meta?.profiles?.quick?.length }} ports)</option><option value="standard">standard ({{ meta?.profiles?.standard?.length }} ports)</option><option value="custom">port kustom</option></select></div>
      </div>
      <div v-if="f.profile === 'custom'"><label class="field-label" for="vs-ports">Port (maks 200)</label><input id="vs-ports" v-model="f.ports" class="input font-mono" placeholder="22, 80, 443, 6379" /></div>
      <div v-if="lab"><div class="field-label">Target</div>
        <div class="grid max-h-44 grid-cols-2 gap-1 overflow-y-auto rounded border border-ink-700 p-2">
          <label v-for="n in lab.nodes.filter((x) => x.node_key !== f.scanner_node)" :key="n.node_key" class="flex items-center gap-2" :data-target="n.node_key">
            <input v-model="f.target_nodes" type="checkbox" :value="n.node_key" class="accent-cyan-400" />{{ n.label }} <span class="font-mono text-[11px] text-ink-500">{{ ips(n) }}</span></label>
        </div></div>
      <p v-if="err" class="text-xs text-sev-critical" role="alert">{{ err }}</p>
    </div>
    <template #footer><CrButton variant="ghost" @click="emit('close')">Batal</CrButton><CrButton variant="primary" :disabled="!ready" :loading="busy" data-test="start-scan" @click="submit">Mulai scan</CrButton></template>
  </CrModal>
</template>
