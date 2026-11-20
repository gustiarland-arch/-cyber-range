<script setup>
import { CheckCircle2, Info, X, XCircle } from 'lucide-vue-next'
import { useUiStore } from '@/stores/ui'
const ui = useUiStore()
const icon = { success: CheckCircle2, error: XCircle, info: Info }
const tone = { success: 'border-ok/40 text-ok', error: 'border-sev-critical/50 text-sev-critical', info: 'border-accent-500/40 text-accent-300' }
</script>
<template>
  <div class="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-80 flex-col gap-2" aria-live="polite">
    <div v-for="t in ui.toasts" :key="t.id" :class="['panel pointer-events-auto flex items-start gap-2 p-3 text-sm shadow-xl', tone[t.type]]" role="status">
      <component :is="icon[t.type]" class="mt-0.5 size-4 shrink-0" />
      <span class="flex-1 text-ink-100">{{ t.message }}</span>
      <button class="text-ink-500 hover:text-ink-200" aria-label="Abaikan" @click="ui.dismiss(t.id)"><X class="size-3.5" /></button>
    </div>
  </div>
</template>
