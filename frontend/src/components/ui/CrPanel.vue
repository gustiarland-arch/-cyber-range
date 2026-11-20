<script setup>
defineProps({ title: String, subtitle: String, padded: { type: Boolean, default: true } })
</script>
<template>
  <section class="panel flex min-w-0 flex-col">
    <header v-if="title || $slots.actions" class="panel-header">
      <div class="min-w-0"><h2 class="panel-title">{{ title }}</h2><p v-if="subtitle" class="mt-0.5 truncate text-[11px] text-ink-500">{{ subtitle }}</p></div>
      <div class="flex items-center gap-2"><slot name="actions" /></div>
    </header>
    <div :class="[padded ? 'p-4' : '', 'min-h-0 flex-1']"><slot /></div>
  </section>
</template>
