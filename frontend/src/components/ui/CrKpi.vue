<script setup>
defineProps({
  label: String, value: [Number, String], icon: [Object, Function], tone: { type: String, default: 'accent' },
  hint: String, pendingPhase: Number, to: [String, Object],
})
const tones = { accent: 'text-accent-400', ok: 'text-ok', bad: 'text-sev-critical', warn: 'text-warn', blue: 'text-blue-team' }
</script>
<template>
  <component :is="to ? 'RouterLink' : 'div'" :to="to"
    :class="['panel group relative block overflow-hidden p-4', to ? 'transition hover:border-accent-500/50' : '']">
    <div class="flex items-start justify-between gap-2">
      <div class="text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-400">{{ label }}</div>
      <component :is="icon" v-if="icon" :class="['size-4', pendingPhase ? 'text-ink-600' : tones[tone]]" />
    </div>
    <div v-if="pendingPhase" class="mt-3">
      <div class="font-mono text-2xl text-ink-600">—</div>
      <div class="mt-1 text-xs text-ink-500">Belum ada sumber data · <span class="whitespace-nowrap">Phase {{ pendingPhase }}</span></div>
    </div>
    <div v-else class="mt-3">
      <div class="font-mono text-3xl font-semibold tabular-nums text-ink-100">{{ value ?? '—' }}</div>
      <div v-if="hint" class="mt-1 text-xs text-ink-400">{{ hint }}</div>
    </div>
    <div v-if="!pendingPhase" :class="['absolute inset-x-0 bottom-0 h-px opacity-60', tone === 'bad' ? 'bg-sev-critical' : 'bg-accent-400']" />
  </component>
</template>
