<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/services/api'
import { ago } from '@/services/format'
import AttackMap from '@/components/charts/AttackMap.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import DemoTag from '@/components/soc/DemoTag.vue'
import SevBadge from '@/components/soc/SevBadge.vue'

const router = useRouter()
const data = ref(null)
const err = ref(null)
const hours = ref(24)
const demo = ref(true)
const minSev = ref(0)
let timer
async function load() {
  try { data.value = await api('/soc/geo/attackers', { query: { hours: hours.value, include_demo: demo.value, min_severity: minSev.value } }); err.value = null } catch (e) { err.value = e }
  clearTimeout(timer); timer = setTimeout(load, 30000)
}
onMounted(load)
onBeforeUnmount(() => clearTimeout(timer))
watch([hours, demo, minSev], load)
const hunt = (ip) => router.push({ name: 'siem', query: { q: `ip:${ip}`, range: hours.value <= 24 ? '24h' : '7d' } })
const total = computed(() => (data.value ? data.value.points.length + data.value.private.length + data.value.unresolved.length : 0))
</script>

<template>
  <PageHeader section="Command Center" title="Peta Serangan" subtitle="Sumber event keamanan per lokasi, dari database GeoIP lokal (tanpa layanan online). Klik titik untuk mencarinya di SIEM.">
    <select v-model.number="hours" class="input w-28" aria-label="Periode"><option :value="1">1 jam</option><option :value="24">24 jam</option><option :value="168">7 hari</option><option :value="720">30 hari</option></select>
    <select v-model.number="minSev" class="input w-36" aria-label="Severity minimal"><option :value="0">semua severity</option><option :value="2">medium ke atas</option><option :value="3">high ke atas</option></select>
    <label class="flex items-center gap-2 text-sm"><input v-model="demo" type="checkbox" /> Sertakan DEMO</label>
  </PageHeader>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!data" kind="loading" />
  <template v-else>
    <div v-if="!data.geoip.available" class="mb-4 rounded-lg border border-warn/40 bg-warn/5 p-3 text-sm text-warn" data-test="geoip-missing">
      Database GeoIP belum dipasang, jadi alamat publik belum bisa dipetakan. Unduh <b>GeoLite2-City.mmdb</b> dengan akun MaxMind gratis Anda,
      simpan di <code>storage/geoip/GeoLite2-City.mmdb</code> (dipasang ke <code>{{ data.geoip.path }}</code>), lalu muat ulang halaman ini. Alamat lab/privat tetap tercantum di bawah.
    </div>
    <div class="grid gap-4 xl:grid-cols-4">
      <CrPanel class="xl:col-span-3" title="Peta" :subtitle="`${data.points.length} sumber terpetakan · ${total} total`" :padded="false">
        <AttackMap :points="data.points" @select="(p) => hunt(p.ip)" />
      </CrPanel>
      <div class="space-y-4">
        <CrPanel title="Negara teratas" :padded="false">
          <CrState v-if="!data.countries.length" kind="empty" message="Belum ada sumber publik yang terpetakan." />
          <ul v-else class="divide-y divide-ink-800 text-sm"><li v-for="c in data.countries.slice(0, 10)" :key="c.country" class="flex justify-between px-3 py-1.5"><span>{{ c.name || c.country }}</span><span class="font-mono text-xs text-ink-400">{{ c.events }} event · {{ c.sources }} IP</span></li></ul>
        </CrPanel>
        <CrPanel title="Sumber privat / lab" :padded="false">
          <CrState v-if="!data.private.length" kind="empty" message="Tidak ada." />
          <ul v-else class="max-h-72 divide-y divide-ink-800 overflow-y-auto text-xs"><li v-for="p in data.private" :key="p.ip" class="flex items-center gap-2 px-3 py-1.5">
            <button class="font-mono text-accent-300 hover:underline" @click="hunt(p.ip)">{{ p.ip }}</button><SevBadge :sev="p.max_severity" /><DemoTag v-if="p.is_demo" /><span class="ml-auto text-ink-500">{{ p.events }} · {{ ago(p.last_seen) }}</span></li></ul>
        </CrPanel>
      </div>
    </div>
    <CrPanel v-if="data.points.length" class="mt-4" title="Sumber publik" :padded="false">
      <table class="data-table"><thead><tr><th>IP</th><th>Lokasi</th><th>Event</th><th>Severity maks</th><th>Terakhir</th></tr></thead>
        <tbody><tr v-for="p in data.points" :key="p.ip"><td><button class="font-mono text-accent-300 hover:underline" @click="hunt(p.ip)">{{ p.ip }}</button> <DemoTag v-if="p.is_demo" /></td>
          <td class="text-xs">{{ [p.city, p.country_name].filter(Boolean).join(', ') || p.country }}</td><td class="font-mono">{{ p.events }}</td><td><SevBadge :sev="p.max_severity" /></td><td class="text-xs">{{ ago(p.last_seen) }}</td></tr></tbody></table>
    </CrPanel>
  </template>
</template>
