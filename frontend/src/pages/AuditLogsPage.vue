<script setup>
import { onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Download, Filter, ShieldCheck, X } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { fmtTime, outcomeTone } from '@/services/format'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPagination from '@/components/ui/CrPagination.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const ui = useUiStore()
const route = useRoute()
const router = useRouter()
const keys = ['action', 'actor', 'outcome', 'resource_type']
const f = reactive({ action: '', actor: '', outcome: '', resource_type: '', page: 1, page_size: 50 })
const res = ref(null)
const err = ref(null)
const detail = ref(null)
const verifying = ref(false)
const verifyResult = ref(null)
const SAVED = 'cr.audit.savedFilters'
const saved = ref(JSON.parse(localStorage.getItem(SAVED) || '[]'))

function fromQuery() { for (const k of keys) f[k] = route.query[k] || '' }
async function load() {
  err.value = null
  try { res.value = await api('/audit-logs', { query: f }) } catch (e) { err.value = e }
}
onMounted(() => { fromQuery(); load() })
watch(() => route.query, () => { fromQuery(); f.page = 1; load() })
watch(() => f.page, load)
function apply() {
  const q = Object.fromEntries(keys.filter((k) => f[k]).map((k) => [k, f[k]]))
  router.replace({ query: q })
}
function clearAll() { router.replace({ query: {} }) }
function saveFilter() {
  const q = Object.fromEntries(keys.filter((k) => f[k]).map((k) => [k, f[k]]))
  if (!Object.keys(q).length) return ui.toast('Atur minimal satu filter untuk menyimpan')
  const name = Object.entries(q).map(([k, v]) => `${k}=${v}`).join(' ')
  saved.value = [{ name, q }, ...saved.value.filter((s) => s.name !== name)].slice(0, 8)
  localStorage.setItem(SAVED, JSON.stringify(saved.value))
  ui.success('Filter disimpan')
}
function removeSaved(n) { saved.value = saved.value.filter((s) => s.name !== n); localStorage.setItem(SAVED, JSON.stringify(saved.value)) }
async function verify() {
  verifying.value = true
  try { verifyResult.value = await api('/audit-logs/verify'); verifyResult.value.valid ? ui.success(`Rantai hash utuh (${verifyResult.value.checked} entri)`) : ui.error(`Manipulasi terdeteksi pada entri #${verifyResult.value.broken_at_id}`); load() }
  catch (e) { ui.error(e) } finally { verifying.value = false }
}
async function exportCsv() {
  try { await download('/audit-logs/export.csv', Object.fromEntries(keys.map((k) => [k, f[k]])), 'audit_logs.csv'); ui.success('Ekspor diunduh') } catch (e) { ui.error(e) }
}
</script>
<template>
  <PageHeader section="Manajemen" title="Audit Log" subtitle="Catatan append-only berantai hash SHA-256 untuk setiap tindakan yang relevan dengan keamanan (UTC).">
    <CrButton :loading="verifying" @click="verify"><ShieldCheck class="size-4" /> Verifikasi integritas</CrButton>
    <CrButton @click="exportCsv"><Download class="size-4" /> Ekspor CSV</CrButton>
  </PageHeader>
  <div v-if="verifyResult" :class="['panel mb-4 px-4 py-3 text-sm', verifyResult.valid ? 'border-ok/40 text-ok' : 'border-sev-critical/50 text-sev-critical']">
    {{ verifyResult.valid ? `Integritas terverifikasi: ${verifyResult.checked} entri, rantai tidak terputus.` : `Integritas GAGAL pada entri #${verifyResult.broken_at_id} setelah ${verifyResult.checked} entri valid.` }}
  </div>
  <div class="panel">
    <form class="flex flex-wrap items-end gap-2 border-b border-ink-700/60 p-3" @submit.prevent="apply">
      <div><label class="field-label" for="fa">Awalan aksi</label><input id="fa" v-model="f.action" class="input w-44 font-mono" placeholder="auth." /></div>
      <div><label class="field-label" for="fu">Aktor</label><input id="fu" v-model="f.actor" class="input w-40" placeholder="username" /></div>
      <div><label class="field-label" for="fo">Hasil</label><select id="fo" v-model="f.outcome" class="input w-32"><option value="">any</option><option>success</option><option>failure</option><option>denied</option></select></div>
      <div><label class="field-label" for="fr">Tipe sumber daya</label><input id="fr" v-model="f.resource_type" class="input w-36 font-mono" placeholder="user" /></div>
      <CrButton type="submit" variant="primary"><Filter class="size-4" /> Terapkan</CrButton>
      <CrButton variant="ghost" @click="clearAll">Bersihkan</CrButton>
      <CrButton variant="ghost" @click="saveFilter">Simpan filter</CrButton>
    </form>
    <div v-if="saved.length" class="flex flex-wrap gap-1.5 border-b border-ink-700/60 px-3 py-2">
      <span v-for="s in saved" :key="s.name" class="inline-flex items-center gap-1 rounded-full border border-ink-600 bg-ink-850 py-0.5 pr-1 pl-2.5 font-mono text-[11px]">
        <button class="text-ink-300 hover:text-accent-300" @click="router.replace({ query: s.q })">{{ s.name }}</button>
        <button class="rounded-full p-0.5 text-ink-500 hover:text-ink-100" :aria-label="`Remove ${s.name}`" @click="removeSaved(s.name)"><X class="size-3" /></button>
      </span>
    </div>
    <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
    <CrState v-else-if="!res" kind="loading" />
    <CrState v-else-if="!res.items.length" kind="empty" message="Tidak ada entri audit yang cocok dengan filter ini." />
    <template v-else>
      <div class="overflow-x-auto">
        <table class="data-table">
          <thead><tr><th>#</th><th>Waktu (lokal)</th><th>Aktor</th><th>Aksi</th><th>Hasil</th><th>Sumber daya</th><th>IP</th></tr></thead>
          <tbody>
            <tr v-for="r in res.items" :key="r.id" class="cursor-pointer" @click="detail = r">
              <td class="font-mono text-xs text-ink-500">{{ r.id }}</td>
              <td class="font-mono text-xs whitespace-nowrap text-ink-400">{{ fmtTime(r.occurred_at) }}</td>
              <td class="text-ink-100">{{ r.actor_label }}</td>
              <td class="font-mono text-xs">{{ r.action }}</td>
              <td><CrBadge :tone="outcomeTone(r.outcome)">{{ r.outcome }}</CrBadge></td>
              <td class="font-mono text-xs text-ink-400">{{ r.resource_type ? `${r.resource_type}:${r.resource_id ?? ''}` : '—' }}</td>
              <td class="font-mono text-xs text-ink-500">{{ r.ip_address || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <CrPagination v-model:page="f.page" :page-size="f.page_size" :total="res.total" />
    </template>
  </div>
  <CrModal :open="!!detail" :title="`Audit entry #${detail?.id}`" width="max-w-2xl" @close="detail = null">
    <dl v-if="detail" class="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1.5 text-sm">
      <dt class="text-ink-500">Terjadi (UTC)</dt><dd class="font-mono text-xs">{{ detail.occurred_at }}</dd>
      <dt class="text-ink-500">Aktor</dt><dd>{{ detail.actor_label }} <span v-if="detail.actor_user_id" class="font-mono text-xs text-ink-500">(id {{ detail.actor_user_id }})</span></dd>
      <dt class="text-ink-500">Aksi</dt><dd class="font-mono text-xs">{{ detail.action }}</dd>
      <dt class="text-ink-500">Hasil</dt><dd><CrBadge :tone="outcomeTone(detail.outcome)">{{ detail.outcome }}</CrBadge></dd>
      <dt class="text-ink-500">Sumber daya</dt><dd class="font-mono text-xs">{{ detail.resource_type || '—' }} {{ detail.resource_id || '' }}</dd>
      <dt class="text-ink-500">IP / Agent</dt><dd class="font-mono text-xs break-all">{{ detail.ip_address || '—' }} · {{ detail.user_agent || '—' }}</dd>
      <dt class="text-ink-500">Request ID</dt><dd class="font-mono text-xs">{{ detail.request_id || '—' }}</dd>
      <dt class="text-ink-500">Hash entri</dt><dd class="font-mono text-[11px] break-all text-ink-400">{{ detail.entry_hash }}</dd>
      <dt class="text-ink-500">Detail</dt><dd><pre class="max-h-64 overflow-auto rounded bg-ink-950 p-2 font-mono text-xs text-ink-300">{{ JSON.stringify(detail.details, null, 2) }}</pre></dd>
    </dl>
  </CrModal>
</template>
