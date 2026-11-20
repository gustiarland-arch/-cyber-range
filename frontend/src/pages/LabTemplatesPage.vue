<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Plus } from 'lucide-vue-next'
import { api } from '@/services/api'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const auth = useAuthStore()
const ui = useUiStore()
const router = useRouter()
const images = ref(null)
const meta = ref(null)
const err = ref(null)
const canManage = computed(() => auth.can('lab.manage'))
const canCreate = computed(() => auth.can('network.topology.edit'))
const NODE_TYPES = ['server', 'workstation', 'router', 'firewall', 'database', 'vm', 'container', 'sensor']

async function load() {
  try { [images.value, meta.value] = await Promise.all([api('/labs/images'), api('/networks/meta')]); err.value = null } catch (e) { err.value = e }
}
onMounted(load)

async function useTemplate(t) {
  try {
    const n = await api('/networks', { method: 'POST', body: { name: `${t.title} · ${new Date().toISOString().slice(0, 19).replace("T", " ")}`, template: t.id === 'blank' ? null : t.id, visibility: 'private' } })
    ui.success('Jaringan dibuat dari template'); router.push({ name: 'network-editor', params: { id: n.id } })
  } catch (e) { ui.error(e) }
}
async function toggle(img) {
  try { await api(`/labs/images/${img.id}`, { method: 'PATCH', body: { is_enabled: !img.is_enabled } }); load() } catch (e) { ui.error(e) }
}
const addOpen = ref(false)
const form = reactive({ reference: '', title: '', description: '', node_types: ['server'], keepalive: true, default_cpus: 0.25, default_memory_mb: 64 })
async function add() {
  try { await api('/labs/images', { method: 'POST', body: form }); ui.success('Image ditambahkan ke allowlist'); addOpen.value = false; load() } catch (e) { ui.error(e) }
}
</script>

<template>
  <PageHeader section="Cyber Range Lab" title="Template Lab" subtitle="Template topologi sebagai titik awal, dan allowlist image yang boleh dijalankan lab." />
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!images" kind="loading" />
  <template v-else>
    <h2 class="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-ink-400">Template topologi</h2>
    <div class="mb-6 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      <div v-for="t in meta.templates" :key="t.id" class="panel flex flex-col p-4">
        <div class="text-sm font-semibold text-ink-100">{{ t.title }}</div>
        <p class="mt-1 flex-1 text-xs text-ink-400">{{ t.description }}</p>
        <CrButton v-if="canCreate" size="sm" class="mt-3 self-start" @click="useTemplate(t)">Gunakan template</CrButton>
      </div>
    </div>

    <CrPanel title="Allowlist image" subtitle="Lab hanya dapat menjalankan image yang terdaftar dan aktif di sini. Node memakai image aktif pertama untuk tipenya kecuali propertinya menyebutkan image tertentu." :padded="false">
      <template #actions><CrButton v-if="canManage" size="sm" variant="primary" @click="addOpen = true"><Plus class="size-3.5" /> Tambah image</CrButton></template>
      <table class="data-table">
        <thead><tr><th>Image</th><th>Tipe node</th><th>Default</th><th>Capability tambahan</th><th>Status</th><th v-if="canManage" /></tr></thead>
        <tbody>
          <tr v-for="i in images" :key="i.id" :data-image="i.reference">
            <td><div class="font-mono text-xs text-ink-100">{{ i.reference }}</div><div class="text-xs text-ink-500">{{ i.title }} · {{ i.description }}</div></td>
            <td><div class="flex flex-wrap gap-1"><CrBadge v-for="t in i.node_types" :key="t">{{ t }}</CrBadge></div></td>
            <td class="font-mono text-xs">{{ i.default_cpus }} vCPU · {{ i.default_memory_mb }} MB</td>
            <td class="font-mono text-[11px] text-ink-400">{{ i.cap_add.join(', ') || 'none (all dropped)' }}</td>
            <td><CrBadge :tone="i.is_enabled ? 'ok' : 'neutral'">{{ i.is_enabled ? 'enabled' : 'disabled' }}</CrBadge></td>
            <td v-if="canManage" class="text-right"><CrButton size="sm" variant="ghost" @click="toggle(i)">{{ i.is_enabled ? 'Disable' : 'Enable' }}</CrButton></td>
          </tr>
        </tbody>
      </table>
    </CrPanel>
  </template>

  <CrModal :open="addOpen" title="Tambah image ke allowlist" @close="addOpen = false">
    <div class="space-y-3">
      <div><label class="field-label" for="img-ref">Referensi</label><input id="img-ref" v-model="form.reference" class="input font-mono" placeholder="alpine:3.20 atau repo/name@sha256:…" /></div>
      <div><label class="field-label" for="img-title">Judul</label><input id="img-title" v-model="form.title" class="input" /></div>
      <div><label class="field-label" for="img-desc">Deskripsi</label><input id="img-desc" v-model="form.description" class="input" /></div>
      <div><div class="field-label">Tipe node</div><div class="flex flex-wrap gap-3">
        <label v-for="t in NODE_TYPES" :key="t" class="flex items-center gap-1.5 text-sm"><input v-model="form.node_types" type="checkbox" :value="t" class="accent-cyan-400" />{{ t }}</label></div></div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="field-label" for="img-cpu">vCPU default</label><input id="img-cpu" v-model.number="form.default_cpus" type="number" step="0.05" min="0.05" max="4" class="input" /></div>
        <div><label class="field-label" for="img-mem">Memori default (MB)</label><input id="img-mem" v-model.number="form.default_memory_mb" type="number" min="16" max="8192" class="input" /></div>
      </div>
      <label class="flex items-center gap-2 text-sm"><input v-model="form.keepalive" type="checkbox" class="accent-cyan-400" /> Jaga container tetap hidup dengan shell idle (untuk image tanpa layanan yang berjalan lama)</label>
      <p class="text-xs text-ink-500">Image berjalan dengan semua Linux capability dicabut, no-new-privileges, batas sumber daya dan tanpa egress jaringan.</p>
    </div>
    <template #footer><CrButton @click="addOpen = false">Batal</CrButton><CrButton variant="primary" :disabled="!form.reference || !form.title || !form.node_types.length" @click="add">Tambah</CrButton></template>
  </CrModal>
</template>
