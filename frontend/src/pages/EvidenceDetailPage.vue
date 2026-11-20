<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, BadgeCheck, Download, Lock, Repeat2 } from 'lucide-vue-next'
import { api, downloadPost } from '@/services/api'
import { fmtTime } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import { ACTION_TONE, EV_STATUS_TONE, INTEGRITY_TONE, KIND_LABEL } from '@/components/forensics/fx'
import { fmtBytes } from '@/components/malware/mw'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const canManage = computed(() => auth.can('evidence.manage'))
const e = ref(null)
const err = ref(null)
async function load() { try { e.value = await api(`/forensics/evidence/${route.params.id}`); err.value = null } catch (x) { err.value = x } }
watch(() => route.params.id, load, { immediate: true })
const isCustodian = computed(() => e.value && (e.value.custodian_id === auth.user?.id || e.value.case.lead_id === auth.user?.id))
const verifying = ref(false)
async function verify() {
  verifying.value = true
  try { const r = await api(`/forensics/evidence/${e.value.id}/verify`, { method: 'POST' }); r.match ? ui.success('Integritas terverifikasi: SHA-256 cocok') : ui.error({ message: 'INTEGRITY MISMATCH: stored bytes differ from the acquisition hash' }); load() } catch (x) { ui.error(x) } finally { verifying.value = false }
}
const dlg = ref(null) // { kind: 'transfer'|'status'|'seal'|'note'|'download', reason, ... }
const custodians = ref([])
async function open(kind) {
  dlg.value = { kind, reason: '', to_user_id: '', location: '', status: e.value.status }
  if (kind === 'transfer' && !custodians.value.length) custodians.value = await api('/forensics/custodians').catch(() => [])
}
const TITLES = { transfer: 'Serahkan custody', status: 'Ubah status', seal: 'Segel evidence', note: 'Tambah catatan custody', download: 'Unduh evidence' }
const busy = ref(false)
async function submit() {
  const d = dlg.value
  busy.value = true
  try {
    if (d.kind === 'download') {
      await downloadPost(`/forensics/evidence/${e.value.id}/download`, { reason: d.reason }, e.value.filename || `${e.value.reference.replace('/', '_')}.bin`)
      ui.success('Unduhan dicatat di log custody')
    } else {
      const body = { reason: d.reason, ...(d.kind === 'transfer' ? { to_user_id: Number(d.to_user_id), location: d.location } : {}), ...(d.kind === 'status' ? { status: d.status } : {}) }
      const path = { transfer: 'transfer', status: 'status', seal: 'seal', note: 'notes' }[d.kind]
      e.value = await api(`/forensics/evidence/${e.value.id}/${path}`, { method: 'POST', body })
      ui.success(`${TITLES[d.kind]}: dicatat`)
    }
    dlg.value = null
    load()
  } catch (x) { ui.error(x) } finally { busy.value = false }
}
</script>

<template>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!e" kind="loading" />
  <template v-else>
    <PageHeader section="Forensik Digital" :title="`${e.reference} · ${e.title}`" :subtitle="`${KIND_LABEL[e.kind]} · ${e.source || 'sumber tidak tercatat'}`">
      <CrButton variant="ghost" @click="router.push({ name: 'case', params: { id: e.case.id } })"><ArrowLeft class="size-4" /> {{ e.case.reference }}</CrButton>
      <template v-if="canManage">
        <CrButton :loading="verifying" data-test="verify" @click="verify"><BadgeCheck class="size-4" /> Verifikasi integritas</CrButton>
        <CrButton v-if="e.downloadable" data-test="download" @click="open('download')"><Download class="size-4" /> Unduh</CrButton>
        <CrButton v-if="isCustodian" data-test="transfer" @click="open('transfer')"><Repeat2 class="size-4" /> Serahkan</CrButton>
        <CrButton v-if="!e.is_sealed" data-test="seal" @click="open('seal')"><Lock class="size-4" /> Segel</CrButton>
        <CrButton variant="ghost" @click="open('status')">Status</CrButton>
        <CrButton variant="ghost" @click="open('note')">Catatan</CrButton>
      </template>
    </PageHeader>
    <div class="grid gap-4 lg:grid-cols-3" data-test="evidence-detail">
      <div class="panel space-y-2 p-4 text-sm lg:col-span-2">
        <div class="flex flex-wrap items-center gap-2"><CrBadge :tone="INTEGRITY_TONE[e.integrity]" data-test="integrity">integrity: {{ e.integrity }}</CrBadge>
          <CrBadge :tone="EV_STATUS_TONE[e.status]" data-test="ev-status">{{ $st(e.status) }}</CrBadge><CrBadge v-if="e.is_sealed" tone="ok" data-test="sealed">sealed</CrBadge>
          <CrBadge :tone="e.chain.valid ? 'ok' : 'critical'" data-test="chain">custody chain {{ e.chain.valid ? `utuh (${e.chain.entries})` : `BROKEN at #${e.chain.broken_at}` }}</CrBadge></div>
        <div v-for="h in e.hashes" :key="h.algorithm" class="flex gap-2 font-mono text-xs"><span class="w-14 uppercase text-ink-500">{{ h.algorithm }}</span><span class="break-all text-ink-200">{{ h.value }}</span></div>
        <div class="text-xs text-ink-400">File {{ e.filename || '—' }} · {{ fmtBytes(e.size) }} · collected {{ fmtTime(e.collected_at) }} oleh {{ e.collected_by }} · last verified {{ e.last_verified_at ? fmtTime(e.last_verified_at) : 'never' }}</div>
        <p v-if="e.description" class="whitespace-pre-line text-xs text-ink-300">{{ e.description }}</p>
        <p v-if="e.sample_id" class="text-xs">Sampel terkait: <RouterLink :to="{ name: 'malware-sample', params: { id: e.sample_id } }" class="text-accent-300 hover:underline">#{{ e.sample_id }}</RouterLink> (disimpan ternetralisasi di karantina; tidak dapat diunduh)</p>
        <p v-if="e.origin?.type === 'siem_export'" class="text-xs text-ink-400">Ekspor SIEM dari {{ e.origin.event_ids.length }} event(s){{ e.origin.alert_id ? ` from alert #${e.origin.alert_id}` : '' }}{{ e.origin.contains_demo ? ' · contains DEMO events' : '' }}</p>
      </div>
      <div class="panel space-y-1 p-4 text-sm">
        <h3 class="text-sm font-semibold text-ink-100">Kustodian</h3>
        <div class="text-lg text-ink-100" data-test="custodian">{{ e.custodian }}</div>
        <p class="text-xs text-ink-500">Kasus {{ e.case.reference }} ({{ $st(e.case.status) }}) · lead {{ e.case.lead }}</p>
      </div>
      <div class="panel p-4 lg:col-span-3">
        <h3 class="mb-2 text-sm font-semibold text-ink-100">Rantai custody <span class="text-xs font-normal text-ink-500">append-only; setiap entri meng-hash entri sebelumnya</span></h3>
        <table class="data-table" data-test="custody"><thead><tr><th>#</th><th>Waktu</th><th>Aksi</th><th>Oleh</th><th>Dari → Ke</th><th>Alasan / lokasi</th><th>SHA-256 teramati</th><th>Hasil</th></tr></thead>
          <tbody><tr v-for="c in e.custody" :key="c.seq"><td class="font-mono text-xs">{{ c.seq }}</td><td class="font-mono text-[11px]">{{ fmtTime(c.at) }}</td><td><CrBadge :tone="ACTION_TONE[c.action]">{{ c.action }}</CrBadge></td>
            <td class="text-xs">{{ c.actor }}</td><td class="text-xs">{{ c.from || '' }}{{ c.from || c.to ? ' → ' : '' }}{{ c.to || '' }}</td><td class="text-xs">{{ c.reason }}<div v-if="c.location" class="text-ink-500">{{ c.location }}</div></td>
            <td class="font-mono text-[11px] text-ink-400">{{ c.sha256_observed ? `${c.sha256_observed.slice(0, 16)}…` : '' }}</td>
            <td><CrBadge v-if="c.result" :tone="c.result === 'mismatch' ? 'critical' : 'ok'">{{ c.result }}</CrBadge></td></tr></tbody></table>
      </div>
    </div>
    <CrModal :open="!!dlg" :title="dlg ? TITLES[dlg.kind] : ''" width="max-w-lg" @close="dlg = null">
      <div v-if="dlg" class="grid gap-3 text-sm" :data-test="`dlg-${dlg.kind}`">
        <p v-if="dlg.kind === 'seal'" class="text-xs text-ink-400">Penyegelan memverifikasi ulang SHA-256 terlebih dahulu. Evidence tersegel dipertahankan dan hanya dapat dilepas sesudahnya.</p>
        <p v-if="dlg.kind === 'download'" class="text-xs text-ink-400">Setiap unduhan dicatat di log custody dan audit log beserta alasan Anda.</p>
        <template v-if="dlg.kind === 'transfer'">
          <div><label class="field-label" for="tr-to">Penerima (memiliki evidence.manage)</label><select id="tr-to" v-model="dlg.to_user_id" class="input"><option value="" disabled>Pilih…</option>
            <option v-for="u in custodians.filter((x) => x.id !== e.custodian_id)" :key="u.id" :value="u.id">{{ u.username }}{{ u.full_name ? ` · ${u.full_name}` : '' }}</option></select></div>
          <div><label class="field-label" for="tr-loc">Lokasi penyimpanan baru</label><input id="tr-loc" v-model="dlg.location" class="input" /></div>
        </template>
        <div v-if="dlg.kind === 'status'"><label class="field-label" for="st-s">Status</label><select id="st-s" v-model="dlg.status" class="input">
          <option v-for="s in (e.is_sealed ? ['released'] : ['collected', 'in_analysis', 'preserved', 'released'])" :key="s">{{ s }}</option></select></div>
        <div><label class="field-label" for="dlg-reason">{{ dlg.kind === 'note' ? 'Catatan' : 'Alasan' }}</label><textarea id="dlg-reason" v-model="dlg.reason" class="input" rows="2" data-test="dlg-reason" /></div>
      </div>
      <template #footer><CrButton variant="ghost" @click="dlg = null">Batal</CrButton>
        <CrButton variant="primary" :loading="busy" :disabled="(dlg?.reason || '').trim().length < 5 || (dlg?.kind === 'transfer' && !dlg.to_user_id)" data-test="dlg-submit" @click="submit">Konfirmasi</CrButton></template>
    </CrModal>
  </template>
</template>
