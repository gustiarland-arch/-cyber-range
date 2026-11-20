<script setup>
const CHOICE_LABEL = {}
import { onMounted, ref } from 'vue'
import { Lock, Save } from 'lucide-vue-next'
import { api } from '@/services/api'
import { fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrButton from '@/components/ui/CrButton.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const auth = useAuthStore()
const ui = useUiStore()
const rows = ref(null)
const draft = ref({})
const err = ref(null)
const saving = ref('')
async function load() {
  err.value = null
  try { rows.value = await api('/settings'); draft.value = Object.fromEntries(rows.value.map((r) => [r.key, r.value])) } catch (e) { err.value = e }
}
onMounted(load)
function localError(r) {
  const v = draft.value[r.key]
  if (r.type === 'int' && (!Number.isInteger(v) || v < r.min || v > r.max)) return `Must be an integer ${r.min}–${r.max}`
  if (r.type === 'str' && String(v).length > r.max_len) return `Max ${r.max_len} characters`
  return ''
}
async function save(r) {
  if (localError(r)) return
  saving.value = r.key
  try { const out = await api(`/settings/${r.key}`, { method: 'PUT', body: { value: draft.value[r.key] } }); Object.assign(r, out); ui.success(`${r.key} disimpan`) }
  catch (e) { ui.error(e) } finally { saving.value = '' }
}
</script>
<template>
  <PageHeader section="Manajemen" title="Pengaturan Sistem" subtitle="Divalidasi di server; setiap perubahan dicatat di audit log." />
  <div v-if="err" class="panel"><CrState kind="error" :message="err.message" @retry="load" /></div>
  <div v-else-if="!rows" class="panel"><CrState kind="loading" /></div>
  <div v-else class="panel divide-y divide-ink-800">
    <div v-for="r in rows" :key="r.key" class="grid gap-3 p-4 md:grid-cols-[1fr_minmax(260px,380px)_auto] md:items-center" :data-row="r.key">
      <div>
        <div class="flex items-center gap-1.5 font-mono text-sm text-ink-100"><Lock v-if="r.readonly" class="size-3.5 text-warn" />{{ r.key }}</div>
        <div class="text-xs text-ink-400">{{ r.description }}</div>
        <div v-if="r.updated_at" class="mt-0.5 text-[11px] text-ink-500">updated {{ fmtTime(r.updated_at) }}</div>
      </div>
      <div>
        <label v-if="r.type === 'bool'" class="flex items-center gap-2 text-sm"><input v-model="draft[r.key]" type="checkbox" class="accent-cyan-400" :disabled="r.readonly || !auth.can('system.settings.manage')" :aria-label="r.key" /> {{ draft[r.key] ? 'Aktif' : 'Nonaktif' }}</label>
        <select v-else-if="r.choices" v-model="draft[r.key]" class="input" :disabled="r.readonly || !auth.can('system.settings.manage')" :aria-label="r.key" :data-setting="r.key">
          <option v-for="c in r.choices" :key="c" :value="c">{{ CHOICE_LABEL[c] || c }}</option></select>
        <input v-else-if="r.type === 'int'" v-model.number="draft[r.key]" type="number" :min="r.min" :max="r.max" class="input font-mono" :disabled="r.readonly || !auth.can('system.settings.manage')" :aria-label="r.key" />
        <input v-else v-model="draft[r.key]" class="input" :maxlength="r.max_len" :disabled="r.readonly || !auth.can('system.settings.manage')" :aria-label="r.key" />
        <p v-if="localError(r)" class="mt-1 text-xs text-sev-critical">{{ localError(r) }}</p>
      </div>
      <div class="flex justify-end">
        <span v-if="r.readonly" class="text-xs text-warn">dikunci kebijakan</span>
        <CrButton v-else-if="auth.can('system.settings.manage')" size="sm" :disabled="draft[r.key] === r.value || !!localError(r)" :loading="saving === r.key" @click="save(r)"><Save class="size-3.5" /> Simpan</CrButton>
      </div>
    </div>
  </div>
</template>
