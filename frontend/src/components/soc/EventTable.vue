<script setup>
import { fmtTime } from '@/services/format'
import SevBadge from './SevBadge.vue'
import DemoTag from './DemoTag.vue'
defineProps({ items: { type: Array, required: true }, compact: Boolean })
defineEmits(['select'])
const ep = (ip, port) => (ip ? (port != null ? `${ip}:${port}` : ip) : '—')
</script>
<template>
  <table class="data-table">
    <thead><tr><th>Waktu (UTC)</th><th>Severity</th><th>Dataset</th><th>Sumber</th><th>Tujuan</th><th v-if="!compact">Pengguna / host</th><th>Pesan</th></tr></thead>
    <tbody>
      <tr v-for="e in items" :key="e.id" class="cursor-pointer" :data-event="e.id" @click="$emit('select', e)">
        <td class="whitespace-nowrap font-mono text-[11px] text-ink-400">{{ fmtTime(e.occurred_at) }}</td>
        <td><SevBadge :sev="e.severity" /></td>
        <td class="whitespace-nowrap font-mono text-[11px]">{{ e.dataset }} <DemoTag v-if="e.is_demo" /></td>
        <td class="whitespace-nowrap font-mono text-xs">{{ ep(e.src_ip, e.src_port) }}</td>
        <td class="whitespace-nowrap font-mono text-xs">{{ ep(e.dst_ip, e.dst_port) }}</td>
        <td v-if="!compact" class="max-w-40 truncate text-xs">{{ e.user || e.host || '—' }}</td>
        <td class="max-w-xl truncate text-xs text-ink-200" :title="e.message">{{ e.message }}</td>
      </tr>
    </tbody>
  </table>
</template>
