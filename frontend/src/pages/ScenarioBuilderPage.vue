<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowDown, ArrowUp, Copy, Pencil, Plus, Rocket, Trash2 } from 'lucide-vue-next'
import { api } from '@/services/api'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const scenarios = ref(null)
const catalog = ref(null)
const err = ref(null)
const canWrite = computed(() => auth.can('redteam.assessment.request'))
async function load() {
  try { [scenarios.value, catalog.value] = await Promise.all([api('/redteam/scenarios'), api('/redteam/actions')]); err.value = null } catch (e) { err.value = e }
}
onMounted(load)
const actionById = computed(() => Object.fromEntries((catalog.value?.actions || []).map((a) => [a.id, a])))
const canEdit = (s) => !s.is_builtin && (s.created_by_id === auth.user?.id || auth.can('redteam.assessment.approve'))

// ---- editor
const form = ref(null)
const problems = ref([])
const toText = (v) => (v || []).join(', ')
function stepRow(s) { return { action: s.action, title: s.title || '', ports: toText(s.params?.ports), paths: (s.params?.paths || []).join(' ') } }
function openNew() { form.value = { id: null, code: '', name: '', description: '', objective: '', difficulty: 'basic', steps: [stepRow({ action: 'host_discovery' })] }; problems.value = [] }
function openCopy(s, edit) {
  form.value = { id: edit ? s.id : null, code: edit ? s.code : `${s.code}-COPY`.slice(0, 64), name: edit ? s.name : `${s.name} (copy)`, description: s.description,
    objective: s.objective, difficulty: s.difficulty, steps: s.steps.map(stepRow) }
  problems.value = []
}
function addStep(action) { form.value.steps.push(stepRow({ action, params: action === 'http_inventory' ? { ports: [80], paths: ['/'] } : action === 'port_scan' ? { ports: [22, 80, 443] } : {} })) }
function move(i, d) { const s = form.value.steps; const j = i + d; if (j < 0 || j >= s.length) return; [s[i], s[j]] = [s[j], s[i]] }
function parsePorts(t) { return t.split(/[\s,]+/).filter(Boolean).map((x) => (/^\d+$/.test(x) ? Number(x) : x)) }
function payload() {
  const f = form.value
  return { code: f.code.trim(), name: f.name.trim(), description: f.description, objective: f.objective, difficulty: f.difficulty,
    steps: f.steps.map((s) => {
      const params = {}
      if (['port_scan', 'http_inventory', 'exposure_check'].includes(s.action) && s.ports.trim()) params.ports = parsePorts(s.ports)
      if (s.action === 'http_inventory' && s.paths.trim()) params.paths = s.paths.trim().split(/\s+/)
      return { action: s.action, title: s.title.trim() || undefined, params }
    }) }
}
const saving = ref(false)
async function save() {
  saving.value = true; problems.value = []
  try {
    const body = payload()
    await api(form.value.id ? `/redteam/scenarios/${form.value.id}` : '/redteam/scenarios', { method: form.value.id ? 'PUT' : 'POST', body })
    ui.success('Skenario disimpan'); form.value = null; load()
  } catch (e) { if (e.code === 'invalid_scenario') problems.value = e.details; else ui.error(e) } finally { saving.value = false }
}
const toArchive = ref(null)
async function archive() {
  try { await api(`/redteam/scenarios/${toArchive.value.id}`, { method: 'DELETE' }); ui.success('Skenario diarsipkan'); toArchive.value = null; load() } catch (e) { ui.error(e) }
}
</script>

<template>
  <PageHeader section="Red Team Operations" title="Penyusun Skenario" subtitle="Susun assessment hanya dari katalog aksi yang aman dan non-destruktif">
    <CrButton v-if="canWrite" variant="primary" @click="openNew"><Plus class="size-4" /> Skenario baru</CrButton>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!scenarios" kind="loading" />
  <div v-else class="grid gap-4 xl:grid-cols-3">
    <div class="space-y-3 xl:col-span-2" data-test="scenarios">
      <CrPanel v-for="s in scenarios" :key="s.id" :title="`${s.code} · ${s.name}`" :subtitle="s.description" :data-scenario="s.code">
        <template #actions>
          <CrBadge>{{ s.difficulty }}</CrBadge><CrBadge v-if="s.is_builtin" tone="accent">bawaan</CrBadge><span v-else class="text-[11px] text-ink-500">oleh {{ s.created_by }}</span>
        </template>
        <ol class="mb-3 space-y-1 text-xs"><li v-for="(st, i) in s.steps" :key="i" class="flex gap-2"><span class="w-5 text-right font-mono text-ink-500">{{ i + 1 }}.</span>
          <span class="text-ink-200">{{ st.title }}</span><span class="font-mono text-ink-500">{{ st.mitre }}</span><span v-if="st.params?.ports" class="font-mono text-ink-500">ports {{ st.params.ports.join(',') }}</span></li></ol>
        <div v-if="s.objective" class="mb-3 text-xs text-ink-400">Objective: {{ s.objective }}</div>
        <div class="flex flex-wrap gap-2">
          <CrButton v-if="canWrite" size="sm" variant="primary" @click="router.push({ name: 'attack-simulation', query: { scenario: s.id } })"><Rocket class="size-3.5" /> Gunakan</CrButton>
          <CrButton v-if="canWrite" size="sm" @click="openCopy(s, false)"><Copy class="size-3.5" /> Duplikasi</CrButton>
          <CrButton v-if="canEdit(s)" size="sm" @click="openCopy(s, true)"><Pencil class="size-3.5" /> Ubah</CrButton>
          <CrButton v-if="canEdit(s)" size="sm" variant="danger" @click="toArchive = s"><Trash2 class="size-3.5" /> Arsipkan</CrButton>
        </div>
      </CrPanel>
    </div>
    <CrPanel title="Katalog aksi" :subtitle="catalog.policy">
      <ul class="space-y-3 text-xs"><li v-for="a in catalog.actions" :key="a.id"><div class="flex justify-between"><b class="text-ink-100">{{ a.title }}</b><span class="font-mono text-ink-500">{{ a.mitre }}</span></div>
        <div class="text-ink-400">{{ a.description }}</div><div v-for="(d, k) in a.params" :key="k" class="font-mono text-[11px] text-ink-500">{{ k }}: {{ d }}</div></li></ul>
      <div class="mt-3 text-[11px] text-ink-500">Port sensitif yang ditandai pemeriksaan eksposur: {{ catalog.sensitive_default_ports.join(', ') }}</div>
    </CrPanel>
  </div>

  <CrModal :open="!!form" :title="form?.id ? `Edit ${form.code}` : 'Skenario baru'" width="max-w-4xl" @close="form = null">
    <template v-if="form">
      <div class="grid gap-3 md:grid-cols-3">
        <div><label class="field-label" for="sc-code">Kode</label><input id="sc-code" v-model="form.code" class="input font-mono uppercase" :disabled="!!form.id" placeholder="RT-CUSTOM-01" /></div>
        <div class="md:col-span-2"><label class="field-label" for="sc-name">Nama</label><input id="sc-name" v-model="form.name" class="input" /></div>
        <div class="md:col-span-2"><label class="field-label" for="sc-desc">Deskripsi</label><input id="sc-desc" v-model="form.description" class="input" /></div>
        <div><label class="field-label" for="sc-diff">Tingkat kesulitan</label><select id="sc-diff" v-model="form.difficulty" class="input"><option>dasar</option><option>menengah</option><option>lanjutan</option></select></div>
        <div class="md:col-span-3"><label class="field-label" for="sc-obj">Tujuan</label><input id="sc-obj" v-model="form.objective" class="input" /></div>
      </div>
      <div class="mt-4 mb-2 flex items-center justify-between"><span class="field-label !mb-0">Steps ({{ form.steps.length }}/12)</span>
        <div class="flex gap-1"><CrButton v-for="a in catalog.actions" :key="a.id" size="sm" :disabled="form.steps.length >= 12" :data-add="a.id" @click="addStep(a.id)"><Plus class="size-3" /> {{ a.id }}</CrButton></div></div>
      <ol class="space-y-2">
        <li v-for="(s, i) in form.steps" :key="i" class="rounded-lg border border-ink-700 p-3" :data-step-editor="i">
          <div class="flex items-center gap-2"><span class="font-mono text-xs text-ink-500">{{ i + 1 }}.</span>
            <select v-model="s.action" class="input !w-44" :aria-label="`Step ${i + 1} action`"><option v-for="a in catalog.actions" :key="a.id" :value="a.id">{{ a.id }}</option></select>
            <input v-model="s.title" class="input flex-1" :placeholder="actionById[s.action]?.title" :aria-label="`Step ${i + 1} title`" />
            <CrButton size="sm" variant="ghost" title="Pindah ke atas" :disabled="i === 0" @click="move(i, -1)"><ArrowUp class="size-3.5" /></CrButton>
            <CrButton size="sm" variant="ghost" title="Pindah ke bawah" :disabled="i === form.steps.length - 1" @click="move(i, 1)"><ArrowDown class="size-3.5" /></CrButton>
            <CrButton size="sm" variant="ghost" title="Hapus langkah" :disabled="form.steps.length === 1" @click="form.steps.splice(i, 1)"><Trash2 class="size-3.5" /></CrButton></div>
          <div v-if="['port_scan', 'http_inventory', 'exposure_check'].includes(s.action)" class="mt-2 grid gap-2 md:grid-cols-2">
            <input v-model="s.ports" class="input font-mono text-xs" :placeholder="s.action === 'exposure_check' ? 'default: port sensitif' : '22, 80, 443, 8000-8100'" :aria-label="`Step ${i + 1} ports`" />
            <input v-if="s.action === 'http_inventory'" v-model="s.paths" class="input font-mono text-xs" placeholder="/ /admin /robots.txt" :aria-label="`Step ${i + 1} paths`" />
          </div>
        </li>
      </ol>
      <ul v-if="problems.length" class="mt-3 space-y-1 rounded-lg border border-sev-critical/40 bg-sev-critical/5 p-3 text-xs text-sev-critical" data-test="problems"><li v-for="p in problems" :key="p">{{ p }}</li></ul>
    </template>
    <template #footer><CrButton @click="form = null">Batal</CrButton><CrButton variant="primary" :disabled="saving || !form?.code || !form?.name" @click="save">Simpan skenario</CrButton></template>
  </CrModal>
  <CrModal :open="!!toArchive" title="Arsipkan skenario" @close="toArchive = null">
    <p class="text-sm">Arsipkan <b>{{ toArchive?.code }}</b>? Assessment sebelumnya tetap menyimpan salinan langkahnya.</p>
    <template #footer><CrButton @click="toArchive = null">Batal</CrButton><CrButton variant="danger" @click="archive">Arsipkan</CrButton></template>
  </CrModal>
</template>
