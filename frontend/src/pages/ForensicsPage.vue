<script setup>
import { onMounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Archive, Fingerprint, FolderOpen, ShieldX } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago, fmtTime } from '@/services/format'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrKpi from '@/components/ui/CrKpi.vue'
import CrPagination from '@/components/ui/CrPagination.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import { ACTION_TONE, EV_STATUS_TONE, INTEGRITY_TONE, KIND_LABEL } from '@/components/forensics/fx'
import { fmtBytes } from '@/components/malware/mw'

const router = useRouter()
const ov = ref(null)
const data = ref(null)
const err = ref(null)
const page = ref(1)
const meta = ref(null)
const f = reactive({ q: '', integrity: '', kind: '' })
async function load() {
  try { data.value = await api('/forensics/evidence', { query: { ...f, page: page.value } }); err.value = null } catch (e) { err.value = e }
  ov.value = await api('/forensics/overview').catch(() => ov.value)
}
watch(() => [f.integrity, f.kind], () => { page.value = 1; load() })
watch(page, load)
onMounted(async () => { meta.value = await api('/forensics/meta').catch(() => null); load() })
</script>

<template>
  <PageHeader section="Security Intelligence" title="Forensik Digital" subtitle="Register evidence lintas kasus: hash akuisisi, verifikasi integritas dan chain of custody yang tahan manipulasi.">
    <CrButton @click="router.push({ name: 'cases' })"><FolderOpen class="size-4" /> Kasus & Evidence</CrButton>
  </PageHeader>
  <div v-if="ov" class="mb-4 grid gap-3 md:grid-cols-4" data-test="fx-kpis">
    <CrKpi label="Kasus terbuka" :value="ov.cases_open" :icon="FolderOpen" :to="{ name: 'cases' }" />
    <CrKpi label="Item evidence" :value="ov.evidence_total" :icon="Archive" />
    <CrKpi label="Integritas tidak cocok" :value="ov.evidence_integrity_mismatch" :icon="ShieldX" :tone="ov.evidence_integrity_mismatch ? 'bad' : 'ok'" />
    <CrKpi label="Jatuh tempo verifikasi (>30 h)" :value="ov.verification_due" :icon="Fingerprint" :tone="ov.verification_due ? 'warn' : 'ok'" />
  </div>
  <p v-if="meta?.storage" class="mb-3 text-xs text-ink-500">Storage: {{ meta.storage.adapter }} · <span :class="meta.storage.ok ? 'text-ok' : 'text-sev-critical'">{{ meta.storage.ok ? 'writable' : `unavailable ${meta.storage.error || ''}` }}</span></p>
  <div class="grid gap-4 xl:grid-cols-3">
    <div class="xl:col-span-2">
      <form class="panel mb-4 flex flex-wrap items-center gap-2 p-3" @submit.prevent="page = 1; load()">
        <input v-model="f.q" class="input w-72 font-mono" placeholder="SHA-256, referensi, judul atau sumber" aria-label="Cari evidence" />
        <select v-model="f.integrity" class="input w-36" aria-label="Integritas"><option value="">semua integritas</option><option>verified</option><option>unverified</option><option>mismatch</option></select>
        <select v-model="f.kind" class="input w-40" aria-label="Jenis"><option value="">semua jenis</option><option v-for="k in meta?.kinds || []" :key="k" :value="k">{{ KIND_LABEL[k] }}</option></select>
        <CrButton type="submit">Cari</CrButton>
      </form>
      <div class="panel">
        <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
        <CrState v-else-if="!data" kind="loading" />
        <CrState v-else-if="!data.items.length" kind="empty" message="Belum ada evidence tercatat. Buka kasus di Kasus & Evidence lalu tambahkan item." />
        <template v-else>
          <table class="data-table" data-test="evidence-register"><thead><tr><th>Referensi</th><th>Item</th><th>SHA-256</th><th>Ukuran</th><th>Kustodian</th><th>Integritas</th><th>Status</th></tr></thead>
            <tbody><tr v-for="e in data.items" :key="e.id" class="cursor-pointer" @click="router.push({ name: 'evidence', params: { id: e.id } })">
              <td class="font-mono text-xs">{{ e.reference }}</td><td>{{ e.title }}<div class="text-xs text-ink-500">{{ KIND_LABEL[e.kind] }} · {{ e.source }}</div></td>
              <td class="font-mono text-[11px] text-ink-400">{{ e.sha256.slice(0, 16) }}…</td><td class="font-mono text-xs">{{ fmtBytes(e.size) }}</td><td class="text-xs">{{ e.custodian }}</td>
              <td><CrBadge :tone="INTEGRITY_TONE[e.integrity]">{{ e.integrity }}</CrBadge><div class="text-[11px] text-ink-500">{{ e.last_verified_at ? ago(e.last_verified_at) : 'never' }}</div></td>
              <td><CrBadge :tone="EV_STATUS_TONE[e.status]">{{ $st(e.status) }}</CrBadge><CrBadge v-if="e.is_sealed" tone="ok">sealed</CrBadge></td></tr></tbody></table>
          <CrPagination v-model:page="page" :total="data.total" :page-size="data.page_size" />
        </template>
      </div>
    </div>
    <div class="panel p-4">
      <h3 class="mb-2 text-sm font-semibold text-ink-100">Event custody terbaru</h3>
      <p v-if="!ov?.recent_custody?.length" class="text-xs text-ink-500">Belum ada.</p>
      <ol class="space-y-1.5 text-xs" data-test="recent-custody"><li v-for="c in ov?.recent_custody || []" :key="c.id" class="flex flex-wrap items-center gap-1.5">
        <span class="font-mono text-ink-500">{{ fmtTime(c.at) }}</span><CrBadge :tone="ACTION_TONE[c.action]">{{ c.action }}</CrBadge>
        <RouterLink :to="{ name: 'evidence', params: { id: c.evidence_id } }" class="font-mono text-accent-300 hover:underline">{{ c.evidence }}</RouterLink><span class="text-ink-400">oleh {{ c.actor }}<span v-if="c.to"> → {{ c.to }}</span><span v-if="c.result"> · {{ c.result }}</span></span></li></ol>
    </div>
  </div>
</template>
