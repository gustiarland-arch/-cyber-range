<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Plus } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const canManage = computed(() => auth.can('evidence.manage'))
const rows = ref(null)
const err = ref(null)
const f = reactive({ status: 'open', q: '' })
async function load() { try { rows.value = await api('/forensics/cases', { query: f }); err.value = null } catch (e) { err.value = e } }
watch(() => f.status, load)
onMounted(load)
const nc = ref(null)
async function create() {
  try {
    const c = await api('/forensics/cases', { method: 'POST', body: { ...nc.value, incident_id: nc.value.incident_id ? Number(nc.value.incident_id) : null } })
    ui.success(`Kasus ${c.reference} dibuka`); nc.value = null; router.push({ name: 'case', params: { id: c.id } })
  } catch (e) { ui.error(e) }
}
const CLASS_TONE = { internal: 'neutral', confidential: 'warn', restricted: 'critical' }
</script>

<template>
  <PageHeader section="Manajemen" title="Kasus & Evidence" subtitle="Kasus forensik mengelompokkan item evidence, kustodiannya dan riwayat custody. Kasus dapat ditautkan ke insiden.">
    <CrButton v-if="canManage" variant="primary" data-test="new-case" @click="nc = { title: '', description: '', classification: 'internal', incident_id: '' }"><Plus class="size-4" /> Kasus baru</CrButton>
  </PageHeader>
  <form class="panel mb-4 flex flex-wrap items-center gap-2 p-3" @submit.prevent="load">
    <input v-model="f.q" class="input w-64" placeholder="referensi atau judul" aria-label="Cari kasus" />
    <select v-model="f.status" class="input w-28" aria-label="Status"><option value="open">open</option><option value="closed">closed</option><option value="all">semua</option></select>
    <CrButton type="submit">Cari</CrButton>
  </form>
  <div class="panel">
    <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
    <CrState v-else-if="!rows" kind="loading" />
    <CrState v-else-if="!rows.length" kind="empty" :message="canManage ? 'Belum ada kasus. Buka satu untuk mulai mengumpulkan evidence.' : 'Belum ada kasus.'" />
    <table v-else class="data-table" data-test="cases"><thead><tr><th>Referensi</th><th>Judul</th><th>Klasifikasi</th><th>Insiden</th><th>Pemimpin</th><th>Evidence</th><th>Status</th><th>Diperbarui</th></tr></thead>
      <tbody><tr v-for="c in rows" :key="c.id" class="cursor-pointer" @click="router.push({ name: 'case', params: { id: c.id } })"><td class="font-mono text-xs">{{ c.reference }}</td><td>{{ c.title }}</td>
        <td><CrBadge :tone="CLASS_TONE[c.classification]">{{ c.classification }}</CrBadge></td><td class="text-xs">{{ c.incident_id ? `#${c.incident_id}` : '—' }}</td><td class="text-xs">{{ c.lead }}</td>
        <td class="font-mono text-xs">{{ c.evidence_count }}</td><td><CrBadge :tone="c.status === 'open' ? 'accent' : 'neutral'">{{ $st(c.status) }}</CrBadge></td><td class="text-xs">{{ ago(c.updated_at) }}</td></tr></tbody></table>
  </div>
  <CrModal :open="!!nc" title="Buka kasus forensik" width="max-w-xl" @close="nc = null">
    <div v-if="nc" class="grid gap-3">
      <div><label class="field-label" for="nc-title">Judul</label><input id="nc-title" v-model="nc.title" class="input" maxlength="255" /></div>
      <div><label class="field-label" for="nc-desc">Deskripsi / cakupan</label><textarea id="nc-desc" v-model="nc.description" class="input" rows="3" /></div>
      <div class="grid grid-cols-2 gap-3"><div><label class="field-label" for="nc-class">Klasifikasi</label><select id="nc-class" v-model="nc.classification" class="input"><option>internal</option><option>confidential</option><option>restricted</option></select></div>
        <div><label class="field-label" for="nc-inc">Insiden # (opsional)</label><input id="nc-inc" v-model="nc.incident_id" type="number" min="1" class="input" /></div></div>
      <p class="text-xs text-ink-500">Anda menjadi pemimpin kasus. Pemimpin dan kustodian setiap item dapat menyerahkan custody.</p>
    </div>
    <template #footer><CrButton variant="ghost" @click="nc = null">Batal</CrButton><CrButton variant="primary" :disabled="(nc?.title || '').trim().length < 3" data-test="create-case" @click="create">Buka kasus</CrButton></template>
  </CrModal>
</template>
