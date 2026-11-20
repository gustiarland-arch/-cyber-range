<script setup>
defineProps({ status: String })
const c = { up: 'bg-ok', healthy: 'bg-ok', degraded: 'bg-warn', down: 'bg-sev-critical', unknown: 'bg-ink-500' }
</script>
<template>
  <span class="relative inline-flex size-2.5">
    <span v-if="status === 'up' || status === 'healthy'" :class="['absolute inline-flex h-full w-full animate-ping rounded-full opacity-40', c[status]]" />
    <span :class="['relative inline-flex size-2.5 rounded-full', c[status] || c.unknown]" />
  </span>
</template>
