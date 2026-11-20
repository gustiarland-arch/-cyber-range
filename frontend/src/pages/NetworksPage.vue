<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Boxes, Copy, FileUp, Lock, PackageOpen, Pencil, Plus, Search, Share2, Trash2 } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const props = defineProps({ mode: { type: String, default: 'editor' } }) // editor | 3d
const auth = useAuthStore()
const ui = useUiStore()
const router = useRouter()
const rows = ref(null)
const err = ref(null)
const q = ref('')
const meta = ref({ templates: [] })
const canCreate = computed(() => auth.can('network.topology.edit'))

async function load() {
  err.value = null
  try { [rows.value, meta.value] = await Promise.all([api('/networks'), api('/networks/meta')]) } catch (e) { err.value = e }
}
onMounted(load)
const filtered = computed(() => (rows.value || []).filter((r) => r.name.toLowerCase().includes(q.value.toLowerCase())))
const statusTone = { valid: 'ok', warnings: 'warn', invalid: 'bad', unknown: 'neutral' }
const open = (n) => router.push(props.mode === '3d' ? { name: 'network-3d', params: { id: n.id } } : { name: 'network-editor', params: { id: n.id } })

const createOpen = ref(false)
const form = reactive({ name: '', description: '', visibility: 'private', template: 'blank' })
const saving = ref(false)
async function create() {
  if (!form.name.trim()) return ui.error('Nama wajib diisi')
  saving.value = true
  try { const n = await api('/networks', { method: 'POST', body: { ...form, template: form.template === 'blank' ? null : form.template } }); ui.success('Jaringan dibuat'); router.push({ name: 'network-editor', params: { id: n.id } }) }
  catch (e) { ui.error(e) } finally { saving.value = false }
}

const importOpen = ref(false)
const imp = reactive({ file: null, content: '', format: 'json', name: '', errors: [] })
async function pickFile(e) {
  const f = e.target.files[0]
  if (!f) return
  if (f.size > 1_000_000) return ui.error('File lebih besar dari 1 MB')
  imp.file = f.name
  imp.format = /\.ya?ml$/i.test(f.name) ? 'yaml' : 'json'
  imp.content = await f.text()
  imp.errors = []
}
async function doImport() {
  saving.value = true; imp.errors = []
  try {
    const n = await api('/networks/import', { method: 'POST', body: { format: imp.format, content: imp.content, name: imp.name || undefined } })
    ui.success(`${n.name} diimpor (${n.node_count} perangkat)`); importOpen.value = false; router.push({ name: 'network-editor', params: { id: n.id } })
  } catch (e) { imp.errors = Array.isArray(e.details) ? e.details.map((d) => d.message || `${(d.loc || []).join('.')}: ${d.msg}`) : [e.message] }
  finally { saving.value = false }
}

async function duplicate(n) { try { const c = await api(`/networks/${n.id}/duplicate`, { method: 'POST', body: {} }); ui.success(`${c.name} dibuat`); load() } catch (e) { ui.error(e) } }
async function toggleShare(n) {
  try { await api(`/networks/${n.id}`, { method: 'PATCH', body: { visibility: n.visibility === 'shared' ? 'private' : 'shared' } }); load() } catch (e) { ui.error(e) }
}
const confirmDel = ref(null)
async function del() { try { await api(`/networks/${confirmDel.value.id}`, { method: 'DELETE' }); ui.success('Jaringan dihapus'); confirmDel.value = null; load() } catch (e) { ui.error(e) } }
</script>

<template>
  <PageHeader section="Cyber Range Lab" :title="mode === '3d' ? 'Visualisasi Jaringan 3D' : 'Editor Topologi Jaringan'"
    :subtitle="mode === '3d' ? 'Pilih topologi untuk dijelajahi dalam 3D. Tampilan membaca model tersimpan yang sama dengan editor.' : 'Rancang jaringan lab: zona, subnet, perangkat dan link. Disimpan ke MySQL dengan validasi.'">
    <template v-if="canCreate && mode === 'editor'">
      <CrButton @click="importOpen = true"><FileUp class="size-4" /> Impor</CrButton>
      <CrButton variant="primary" @click="createOpen = true"><Plus class="size-4" /> Jaringan baru</CrButton>
    </template>
  </PageHeader>
  <div class="panel">
    <div class="border-b border-ink-700/60 p-3"><div class="relative w-72"><Search class="absolute top-2.5 left-3 size-4 text-ink-500" /><input v-model="q" class="input pl-9" placeholder="Filter berdasarkan nama" aria-label="Filter jaringan" /></div></div>
    <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
    <CrState v-else-if="!rows" kind="loading" />
    <CrState v-else-if="!filtered.length" kind="empty" :message="canCreate ? 'Buat jaringan atau mulai dari template Corporate DMZ.' : 'Belum ada jaringan yang dibagikan kepada Anda.'" />
    <table v-else class="data-table">
      <thead><tr><th>Nama</th><th>Pemilik</th><th>Perangkat / link</th><th>Validasi</th><th>Versi</th><th>Diperbarui</th><th class="text-right">Aksi</th></tr></thead>
      <tbody>
        <tr v-for="n in filtered" :key="n.id" class="cursor-pointer" @click="open(n)">
          <td><div class="flex items-center gap-1.5 text-ink-100"><Lock v-if="n.visibility === 'private'" class="size-3 text-ink-500" /><Share2 v-else class="size-3 text-accent-400" />{{ n.name }}</div>
            <div class="max-w-md truncate text-xs text-ink-500">{{ n.description }}</div></td>
          <td class="text-xs">{{ n.owner }}</td>
          <td class="font-mono text-xs">{{ n.node_count }} / {{ n.link_count }}</td>
          <td><CrBadge :tone="statusTone[n.validation_status]">{{ n.validation_status }}</CrBadge>
            <span v-if="n.error_count || n.warning_count" class="ml-1 font-mono text-[10px] text-ink-500">{{ n.error_count }}E {{ n.warning_count }}W</span></td>
          <td class="font-mono text-xs">v{{ n.version }}</td>
          <td class="font-mono text-xs text-ink-400">{{ ago(n.updated_at) }}</td>
          <td class="text-right whitespace-nowrap" @click.stop>
            <CrButton size="sm" variant="ghost" :title="n.can_edit ? 'Ubah' : 'Lihat'" @click="router.push({ name: 'network-editor', params: { id: n.id } })"><Pencil class="size-3.5" /></CrButton>
            <CrButton size="sm" variant="ghost" title="Tampilan 3D" @click="router.push({ name: 'network-3d', params: { id: n.id } })"><Boxes class="size-3.5" /></CrButton>
            <CrButton v-if="auth.can('lab.kit.download')" size="sm" variant="ghost" title="Unduh Lab Kit (jalankan di komputer lain)" data-test="network-kit" @click.stop="router.push({ name: 'lab-kit', query: { network: n.id } })"><PackageOpen class="size-3.5" /></CrButton>
            <template v-if="mode === 'editor'">
              <CrButton v-if="canCreate" size="sm" variant="ghost" title="Duplikasi" @click="duplicate(n)"><Copy class="size-3.5" /></CrButton>
              <CrButton v-if="n.can_edit" size="sm" variant="ghost" :title="n.visibility === 'shared' ? 'Jadikan privat' : 'Bagikan ke pengguna lab'" @click="toggleShare(n)"><Share2 class="size-3.5" /></CrButton>
              <CrButton v-if="n.can_edit" size="sm" variant="ghost" title="Hapus" @click="confirmDel = n"><Trash2 class="size-3.5" /></CrButton>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <CrModal :open="createOpen" title="Jaringan baru" @close="createOpen = false">
    <div class="space-y-3">
      <div><label class="field-label" for="nn-name">Nama</label><input id="nn-name" v-model="form.name" class="input" maxlength="128" /></div>
      <div><label class="field-label" for="nn-desc">Deskripsi</label><textarea id="nn-desc" v-model="form.description" class="input" rows="2" /></div>
      <div><div class="field-label">Mulai dari</div>
        <label v-for="t in meta.templates" :key="t.id" class="mb-1 flex cursor-pointer items-start gap-2 rounded-md border border-ink-700 p-2 hover:border-ink-500">
          <input v-model="form.template" type="radio" :value="t.id" class="mt-1 accent-cyan-400" /><span><span class="text-sm text-ink-100">{{ t.title }}</span><span class="block text-xs text-ink-500">{{ t.description }}</span></span></label></div>
      <label class="flex items-center gap-2 text-sm"><input v-model="form.visibility" type="checkbox" true-value="shared" false-value="private" class="accent-cyan-400" /> Bagikan hanya-baca ke pengguna lab</label>
    </div>
    <template #footer><CrButton @click="createOpen = false">Batal</CrButton><CrButton variant="primary" :loading="saving" @click="create">Buat</CrButton></template>
  </CrModal>

  <CrModal :open="importOpen" title="Impor topologi (JSON atau YAML)" @close="importOpen = false">
    <div class="space-y-3">
      <input type="file" accept=".json,.yaml,.yml,application/json,application/yaml" class="block w-full text-sm text-ink-300 file:mr-3 file:rounded file:border-0 file:bg-ink-700 file:px-3 file:py-1.5 file:text-ink-100" aria-label="File topologi" @change="pickFile" />
      <div v-if="imp.file" class="font-mono text-xs text-ink-400">{{ imp.file }} · {{ imp.format.toUpperCase() }} · {{ imp.content.length }} bytes</div>
      <div><label class="field-label" for="imp-name">Nama (opsional, default dari field name di file)</label><input id="imp-name" v-model="imp.name" class="input" /></div>
      <ul v-if="imp.errors.length" class="max-h-40 overflow-y-auto rounded border border-sev-critical/40 bg-sev-critical/5 p-2 text-xs text-sev-critical" role="alert"><li v-for="(e, i) in imp.errors" :key="i">{{ e }}</li></ul>
    </div>
    <template #footer><CrButton @click="importOpen = false">Batal</CrButton><CrButton variant="primary" :disabled="!imp.content" :loading="saving" @click="doImport">Impor</CrButton></template>
  </CrModal>

  <CrModal :open="!!confirmDel" title="Hapus jaringan" @close="confirmDel = null">
    <p class="text-sm">Hapus <b class="text-ink-100">{{ confirmDel?.name }}</b>? Data dihapus secara soft-delete dan tindakan ini diaudit.</p>
    <template #footer><CrButton @click="confirmDel = null">Batal</CrButton><CrButton variant="danger" @click="del">Hapus</CrButton></template>
  </CrModal>
</template>
