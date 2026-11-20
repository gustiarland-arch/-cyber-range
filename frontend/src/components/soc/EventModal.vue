<script setup>
import { ref, watch } from 'vue'
import { api } from '@/services/api'
import { fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import SevBadge from './SevBadge.vue'
import DemoTag from './DemoTag.vue'

const props = defineProps({ eventId: Number })
const emit = defineEmits(['close', 'pivot'])
const ev = ref(null)
const err = ref(null)
const intel = ref([])
const auth = useAuthStore()
watch(() => props.eventId, async (id) => {
  ev.value = null; err.value = null
  if (!id) return
  intel.value = []
  try { ev.value = await api(`/soc/events/${id}`) } catch (e) { err.value = e }
  if (ev.value && auth.can('intel.view')) intel.value = await api('/intel/lookup', { query: { event_id: id } }).catch(() => [])
}, { immediate: true })
const FIELDS = ['dataset', 'category', 'action', 'outcome', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'host', 'user', 'signature', 'signature_id']
function pivot(f) {
  const v = String(ev.value[f])
  emit('pivot', `${PIVOT[f]}:${/\s/.test(v) ? JSON.stringify(v) : v}`)
}
const PIVOT = { src_ip: 'src', dst_ip: 'dst', user: 'user', host: 'host', signature: 'sig', dataset: 'dataset', category: 'cat', dst_port: 'port' }
</script>
<template>
  <CrModal :open="!!eventId" title="Detail event" width="max-w-3xl" @close="emit('close')">
    <CrState v-if="err" kind="error" :message="err.message" />
    <CrState v-else-if="!ev" kind="loading" />
    <div v-else class="space-y-3 text-sm">
      <div class="flex flex-wrap items-center gap-2"><SevBadge :sev="ev.severity" /><DemoTag v-if="ev.is_demo" /><span class="font-mono text-xs text-ink-400">{{ fmtTime(ev.occurred_at) }} UTC · source {{ ev.source }} · ingested {{ fmtTime(ev.ingested_at) }}</span></div>
      <p class="text-ink-100">{{ ev.message }}</p>
      <dl class="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-3">
        <template v-for="f in FIELDS" :key="f">
          <div v-if="ev[f] !== null && ev[f] !== ''"><dt class="text-[10px] uppercase tracking-wider text-ink-500">{{ f }}</dt>
            <dd class="font-mono text-xs text-ink-200"><button v-if="PIVOT[f]" class="hover:text-accent-300 hover:underline" :title="`Search ${PIVOT[f]}:${ev[f]}`" @click="pivot(f)">{{ ev[f] }}</button><span v-else>{{ ev[f] }}</span></dd></div>
        </template>
      </dl>
      <div v-if="ev.alerts.length" class="text-xs">Alert: <RouterLink v-for="a in ev.alerts" :key="a.id" :to="{ name: 'incident-response', query: { alert: a.id } }" class="mr-2 text-accent-300 hover:underline">#{{ a.id }} {{ a.title }} ({{ $st(a.status) }})</RouterLink></div>
      <div v-if="intel.length" class="rounded border border-sev-high/40 bg-sev-high/5 p-2 text-xs" data-test="event-intel">Kecocokan threat intel:
        <RouterLink v-for="i in intel" :key="i.id" :to="{ name: 'threat-intel', query: { id: i.id } }" class="ml-2 font-mono text-sev-high hover:underline">{{ i.type }} {{ i.value }} ({{ i.field }}, {{ i.source }}, conf {{ i.confidence }})</RouterLink></div>
      <div><div class="mb-1 text-[10px] uppercase tracking-wider text-ink-500">Data mentah (sesuai diterima)</div>
        <pre class="max-h-72 overflow-auto rounded border border-ink-700 bg-ink-950 p-3 font-mono text-[11px] text-ink-300">{{ JSON.stringify(ev.raw, null, 2) }}</pre></div>
    </div>
  </CrModal>
</template>
