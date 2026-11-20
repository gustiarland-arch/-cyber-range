<script setup>
defineProps({ title: String, subtitle: String, section: String })
</script>
<template>
  <div class="mb-5 flex flex-wrap items-end justify-between gap-3">
    <div class="min-w-0">
      <div v-if="section" class="mb-1 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400/80">{{ section }}</div>
      <h1 class="text-xl font-semibold text-ink-100">{{ title }}</h1>
      <p v-if="subtitle" class="mt-1 text-sm text-ink-400">{{ subtitle }}</p>
    </div>
    <div class="flex flex-wrap items-center gap-2"><slot /></div>
  </div>
</template>
