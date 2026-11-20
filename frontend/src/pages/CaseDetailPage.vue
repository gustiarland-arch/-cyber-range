<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Download, FileUp, ListPlus } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import { EV_STATUS_TONE, INTEGRITY_TONE, KIND_LABEL } from '@/components/forensics/fx'
import { fmtBytes } from '@/components/malware/mw'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const canManage = computed(() => auth.can('evidence.manage'))
const c = ref(null)
const err = ref(null)
const meta = ref(null)
async function load() { try { c.value = await api(`/forensics/cases/${route.params.id}`); err.value = null } catch (e) { err.value = e } }
watch(() => route.params.id, async () => { meta.value = meta.value || (await api('/forensics/meta').catch(() => null)); load() }, { immediate: true })

const up = ref(null)
const busy = ref(false)
function openUpload() { up.value = { file: null, kind: 'file', title: '', description: '', source: '', collected_at: '', location: '' } }
async function doUpload() {
  busy.value = true
  try {
    const fd = new FormData()
    fd.append('file', up.value.file)
    for (const k of ['kind', 'title', 'description', 'source', 'location']) fd.append(k, up.value[k])
    if (up.value.collected_at) fd.append('collected_at', new Date(up.value.collected_at).toISOString())
    const e = await api(`/forensics/cases/${c.value.id}/evidence`, { method: 'POST', form: fd })
    ui.success(`Evidence ${e.reference} dicatat · SHA-256 ${e.sha256.slice(0, 12)}…`); up.value = null; load()
  } catch (e) { ui.error(e) } finally { busy.value = false }
}
const exp = ref(null)
async function doExport() {
  try {
    const ids = exp.value.event_ids.split(/[\s,]+/).filter(Boolean).map(Number)
    const e = await api(`/forensics/cases/${c.value.id}/evidence/events`, { method: 'POST', body: { event_ids: ids, alert_id: exp.value.alert_id ? Number(exp.value.alert_id) : null, title: exp.value.title } })
    ui.success(`Ekspor SIEM ${e.reference} dicatat`); exp.value = null; load()
  } catch (e) { ui.error(e) }
}
const close = ref(null)
async function setStatus(status) {
  try { c.value = await api(`/forensics/cases/${c.value.id}`, { method: 'PATCH', body: { status, closure_note: close.value?.note } }); close.value = null; ui.success(`Kasus ${status === 'closed' ? 'ditutup' : 'dibuka kembali'}`) } catch (e) { ui.error(e) }
}
async function report() { try { await download(`/forensics/cases/${c.value.id}/report`, null, `${c.value.reference}-custody.md`); load() } catch (e) { ui.error(e) } }
</script>

<template>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!c" kind="loading" />
  <template v-else>
    <PageHeader section="Kasus & Evidence" :title="`${c.reference} · ${c.title}`" :subtitle="c.description">
      <CrButton variant="ghost" @click="router.push({ name: 'cases' })"><ArrowLeft class="size-4" /> Kasus</CrButton>
      <CrButton data-test="case-report" @click="report"><Download class="size-4" /> Laporan custody</CrButton>
      <template v-if="canManage">
        <CrButton v-if="c.status === 'open' && auth.can('blueteam.alerts.view')" @click="exp = { event_ids: '', alert_id: '', title: '' }"><ListPlus class="size-4" /> SIEM export</CrButton>
        <CrButton v-if="c.status === 'open'" variant="primary" data-test="add-evidence" @click="openUpload"><FileUp class="size-4" /> Tambah evidence</CrButton>
        <CrButton v-if="c.status === 'open'" variant="ghost" @click="close = { note: '' }">Tutup kasus</CrButton>
        <CrButton v-else variant="ghost" @click="setStatus('open')">Buka kembali</CrButton>
      </template>
    </PageHeader>
    <div class="mb-4 flex flex-wrap items-center gap-2 text-xs text-ink-400">
      <CrBadge :tone="c.status === 'open' ? 'accent' : 'neutral'" data-test="case-status">{{ $st(c.status) }}</CrBadge><CrBadge>{{ c.classification }}</CrBadge>
      <span>lead {{ c.lead }} · opened {{ fmtTime(c.created_at) }}</span>
      <span v-if="c.incident">· insiden <RouterLink :to="{ name: 'incident-detail', params: { id: c.incident.id } }" class="text-accent-300 hover:underline">#{{ c.incident.id }} {{ c.incident.title }}</RouterLink></span>
      <span v-if="c.closed_at">· closed {{ fmtTime(c.closed_at) }}: {{ c.closure_note }}</span>
    </div>
    <div class="panel">
      <CrState v-if="!c.evidence.length" kind="empty" :message="canManage ? 'Belum ada evidence. Unggah file, ekspor event SIEM, atau tambahkan sampel dari Analisis Malware.' : 'Belum ada evidence.'" />
      <table v-else class="data-table" data-test="case-evidence"><thead><tr><th>Referensi</th><th>Item</th><th>Dikumpulkan</th><th>SHA-256</th><th>Ukuran</th><th>Kustodian</th><th>Integritas</th><th>Status</th></tr></thead>
        <tbody><tr v-for="e in c.evidence" :key="e.id" class="cursor-pointer" :data-evidence="e.reference" @click="router.push({ name: 'evidence', params: { id: e.id } })">
          <td class="font-mono text-xs">{{ e.reference }}</td><td>{{ e.title }}<div class="text-xs text-ink-500">{{ KIND_LABEL[e.kind] }} · {{ e.source }}</div></td>
          <td class="text-xs">{{ fmtTime(e.collected_at) }}<div class="text-ink-500">{{ e.collected_by }}</div></td><td class="font-mono text-[11px] text-ink-400">{{ e.sha256.slice(0, 16) }}…</td>
          <td class="font-mono text-xs">{{ fmtBytes(e.size) }}</td><td class="text-xs">{{ e.custodian }}</td><td><CrBadge :tone="INTEGRITY_TONE[e.integrity]">{{ e.integrity }}</CrBadge></td>
          <td><CrBadge :tone="EV_STATUS_TONE[e.status]">{{ $st(e.status) }}</CrBadge><CrBadge v-if="e.is_sealed" tone="ok">sealed</CrBadge></td></tr></tbody></table>
    </div>

    <CrModal :open="!!up" title="Tambah evidence" width="max-w-xl" @close="up = null">
      <div v-if="up" class="grid gap-3 text-sm" data-test="evidence-form">
        <p class="text-xs text-ink-400">SHA-256, SHA-1 dan MD5 dihitung saat unggah dan entri custody pertama ditulis. Maks {{ meta?.max_upload_mb }} MB. Submit suspected malware through Malware Analysis instead.</p>
        <div><label class="field-label" for="ev-file">File</label><input id="ev-file" type="file" class="input" @change="up.file = $event.target.files?.[0] || null" /></div>
        <div class="grid grid-cols-2 gap-3"><div><label class="field-label" for="ev-kind">Jenis</label><select id="ev-kind" v-model="up.kind" class="input"><option v-for="k in meta?.upload_kinds || []" :key="k" :value="k">{{ KIND_LABEL[k] }}</option></select></div>
          <div><label class="field-label" for="ev-at">Dikumpulkan pada (opsional)</label><input id="ev-at" v-model="up.collected_at" type="datetime-local" class="input" /></div></div>
        <div><label class="field-label" for="ev-title">Judul</label><input id="ev-title" v-model="up.title" class="input" maxlength="255" /></div>
        <div class="grid grid-cols-2 gap-3"><div><label class="field-label" for="ev-src">Sumber (host / perangkat)</label><input id="ev-src" v-model="up.source" class="input" /></div>
          <div><label class="field-label" for="ev-loc">Lokasi penyimpanan</label><input id="ev-loc" v-model="up.location" class="input" placeholder="mis. loker evidence A" /></div></div>
        <div><label class="field-label" for="ev-desc">Deskripsi</label><textarea id="ev-desc" v-model="up.description" class="input" rows="2" /></div>
      </div>
      <template #footer><CrButton variant="ghost" @click="up = null">Batal</CrButton><CrButton variant="primary" :loading="busy" :disabled="!up?.file || (up?.title || '').trim().length < 3" data-test="do-add-evidence" @click="doUpload">Catat evidence</CrButton></template>
    </CrModal>
    <CrModal :open="!!exp" title="Ekspor event SIEM sebagai evidence" width="max-w-xl" @close="exp = null">
      <div v-if="exp" class="grid gap-3 text-sm">
        <p class="text-xs text-ink-400">Menyimpan event ternormalisasi yang dipilih (beserta data mentah) sebagai file JSON Lines dengan hash. Event DEMO ditandai di deskripsi.</p>
        <div><label class="field-label" for="ex-alert">Alert # (semua event-nya)</label><input id="ex-alert" v-model="exp.alert_id" type="number" min="1" class="input w-40" /></div>
        <div><label class="field-label" for="ex-ids">dan/atau id event</label><input id="ex-ids" v-model="exp.event_ids" class="input font-mono" placeholder="101, 102, 103" /></div>
        <div><label class="field-label" for="ex-title">Judul (opsional)</label><input id="ex-title" v-model="exp.title" class="input" /></div>
      </div>
      <template #footer><CrButton variant="ghost" @click="exp = null">Batal</CrButton><CrButton variant="primary" :disabled="!exp?.alert_id && !exp?.event_ids.trim()" @click="doExport">Ekspor</CrButton></template>
    </CrModal>
    <CrModal :open="!!close" title="Tutup kasus" width="max-w-lg" @close="close = null">
      <div v-if="close"><label class="field-label" for="cc-note">Catatan penutupan</label><textarea id="cc-note" v-model="close.note" class="input" rows="3" placeholder="Hasil dan lokasi penyimpanan evidence" /></div>
      <template #footer><CrButton variant="ghost" @click="close = null">Batal</CrButton><CrButton variant="primary" :disabled="(close?.note || '').trim().length < 10" @click="setStatus('closed')">Tutup kasus</CrButton></template>
    </CrModal>
  </template>
</template>
