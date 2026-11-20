<script setup>
import { computed, onMounted, ref } from 'vue'
import { ago } from '@/services/format'
import { fmtBytes } from '@/components/malware/mw'
import { Cpu, Database, HardDrive, RefreshCw, Server, Workflow } from 'lucide-vue-next'
import { api } from '@/services/api'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import StatusDot from '@/components/ui/StatusDot.vue'

const data = ref(null)
const backups = ref(null)
const latest = computed(() => backups.value?.find((b) => b.kind === 'backup'))
const stale = computed(() => !latest.value || Date.now() - new Date(latest.value.finished_at + 'Z').getTime() > 26 * 3600 * 1000)
const err = ref(null)
const loading = ref(false)
const checkedAt = ref(null)
async function load() {
  loading.value = true; err.value = null
  try { data.value = await api('/system/health'); checkedAt.value = new Date() } catch (e) { err.value = e } finally { loading.value = false }
}
onMounted(() => { load(); api('/system/backups').then((b) => { backups.value = b }).catch(() => { backups.value = [] }) })
const meta = {
  mysql: { label: 'MySQL 8.4 LTS', icon: Database, role: 'Penyimpanan relasional utama' },
  redis: { label: 'Redis', icon: HardDrive, role: 'Cache · queue · realtime fan-out' },
  workers: { label: 'Worker Celery', icon: Workflow, role: 'Pemrosesan latar belakang' },
}
const yes = (v) => (v ? 'yes' : 'no')
</script>
<template>
  <PageHeader section="Command Center" title="Kesehatan Sistem" subtitle="Pemeriksaan dependensi langsung dan deteksi kemampuan host.">
    <span v-if="checkedAt" class="font-mono text-xs text-ink-500">checked {{ checkedAt.toLocaleTimeString() }}</span>
    <CrButton size="sm" :loading="loading" @click="load"><RefreshCw class="size-3.5" /> Periksa ulang</CrButton>
  </PageHeader>
  <div v-if="err" class="panel"><CrState kind="error" :message="err.message" @retry="load" /></div>
  <div v-else-if="!data" class="panel"><CrState kind="loading" /></div>
  <template v-else>
    <div class="panel mb-4 flex items-center gap-3 p-4">
      <StatusDot :status="data.overall" />
      <div class="text-sm">Status keseluruhan: <span class="font-semibold uppercase text-ink-100">{{ data.overall }}</span>
        <span class="ml-2 text-ink-500">· environment {{ data.environment }}</span></div>
    </div>
    <div class="mb-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <div v-for="(c, name) in data.components" :key="name" class="panel p-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2 text-sm font-medium text-ink-100"><component :is="meta[name]?.icon || Server" class="size-4 text-accent-400" /> {{ meta[name]?.label || name }}</div>
          <CrBadge :tone="c.status === 'up' ? 'ok' : c.optional ? 'neutral' : 'bad'">{{ $st(c.status) }}</CrBadge>
        </div>
        <p class="mt-1 text-xs text-ink-500">{{ meta[name]?.role }}</p>
        <dl class="mt-3 space-y-1 font-mono text-xs">
          <div class="flex justify-between"><dt class="text-ink-500">latency</dt><dd>{{ c.latency_ms }} ms</dd></div>
          <div v-if="c.version" class="flex justify-between"><dt class="text-ink-500">version</dt><dd>{{ c.version }}</dd></div>
          <template v-if="name === 'mysql' && c.status === 'up'">
            <div class="flex justify-between"><dt class="text-ink-500">engine / charset</dt><dd>{{ c.storage_engine }} / {{ c.charset }}</dd></div>
            <div class="flex justify-between"><dt class="text-ink-500">migration</dt><dd>{{ c.migration_current }} / head {{ c.migration_head }}</dd></div>
            <div class="flex justify-between"><dt class="text-ink-500">terkini</dt><dd :class="c.migrations_up_to_date ? 'text-ok' : 'text-sev-critical'">{{ yes(c.migrations_up_to_date) }}</dd></div>
          </template>
          <div v-if="c.workers" class="flex justify-between"><dt class="text-ink-500">workers</dt><dd class="truncate pl-2">{{ c.workers.join(', ') }}</dd></div>
          <div v-if="c.models" class="flex justify-between"><dt class="text-ink-500">models</dt><dd>{{ c.models.length }}</dd></div>
          <div v-if="c.error" class="flex justify-between"><dt class="text-ink-500">error</dt><dd class="text-sev-high">{{ c.error }}</dd></div>
        </dl>
      </div>
    </div>
    <CrPanel title="Kemampuan host">
      <p class="mb-3 text-xs text-ink-500">{{ data.host.note }}</p>
      <div class="grid gap-x-8 gap-y-1 font-mono text-xs md:grid-cols-2">
        <div class="flex justify-between"><span class="text-ink-500">os</span><span>{{ data.host.os }} ({{ data.host.arch }})</span></div>
        <div class="flex justify-between"><span class="text-ink-500">python</span><span>{{ data.host.python }}</span></div>
        <div class="flex justify-between"><span class="text-ink-500">cpu / memori</span><span>{{ data.host.cpu_count }} cores / {{ data.host.memory_gb }} GB</span></div>
        <div class="flex justify-between"><span class="text-ink-500">gpu</span><span>{{ data.host.gpu || 'none detected' }}</span></div>
        <div class="flex justify-between"><span class="text-ink-500">/dev/kvm</span><span :class="data.host.kvm_device ? 'text-ok' : 'text-warn'">{{ yes(data.host.kvm_device) }}</span></div>
        <div class="flex justify-between"><span class="text-ink-500">cpu virt flags</span><span>{{ yes(data.host.cpu_virt_flags) }}</span></div>
        <div class="flex justify-between"><span class="text-ink-500">docker socket</span><span>{{ yes(data.host.docker_socket) }}</span></div>
        <div class="flex justify-between"><span class="text-ink-500 flex items-center gap-1"><Cpu class="size-3" /> vm mode</span><span class="text-right">{{ data.host.vm_mode }}</span></div>
      </div>
    </CrPanel>
    <CrPanel title="Backup" class="mt-4" data-test="backup-status">
      <template #actions><CrBadge v-if="backups" :tone="latest?.status === 'ok' && !stale ? 'ok' : 'warn'">{{ !latest ? 'no backup recorded' : stale ? 'older than 26 h' : 'recent' }}</CrBadge></template>
      <p class="mb-3 text-xs text-ink-500">Backup dijalankan dari host dengan <code>scripts/backup.sh</code> (dump MySQL + object storage + manifest dengan SHA-256) dan tercatat di sini. Restore memakai <code>scripts/restore.sh</code>.</p>
      <CrState v-if="!backups" kind="loading" />
      <CrState v-else-if="!backups.length" kind="empty" title="Belum ada backup tercatat" message="Jalankan scripts/backup.sh di host; lihat Referensi Teknis (paket docs)." />
      <table v-else class="w-full text-xs">
        <thead class="text-left text-ink-500"><tr><th class="py-1">Label</th><th>Jenis</th><th>Status</th><th>Selesai</th><th>Komponen</th><th class="text-right">Ukuran</th><th>Schema</th></tr></thead>
        <tbody class="divide-y divide-ink-800 font-mono">
          <tr v-for="b in backups.slice(0, 10)" :key="b.id"><td class="py-1">{{ b.label }}</td><td>{{ b.kind }}</td>
            <td><CrBadge :tone="b.status === 'ok' ? 'ok' : 'bad'">{{ $st(b.status) }}</CrBadge></td><td>{{ ago(b.finished_at) }}</td>
            <td>{{ b.components.map((c) => c.name).join(', ') }}</td><td class="text-right">{{ fmtBytes(b.total_size) }}</td><td>{{ b.schema_revision }}</td></tr>
        </tbody>
      </table>
    </CrPanel>
  </template>
</template>
