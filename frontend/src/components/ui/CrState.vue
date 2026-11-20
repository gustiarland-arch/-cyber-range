<script setup>
// Unified loading / empty / error / permission-denied state.
import { AlertTriangle, Inbox, Lock, RotateCw } from 'lucide-vue-next'
import CrSpinner from './CrSpinner.vue'
import CrButton from './CrButton.vue'
defineProps({
  kind: { type: String, required: true }, // loading | empty | error | denied
  title: String,
  message: String,
  missing: { type: Array, default: () => [] },
})
defineEmits(['retry'])
</script>
<template>
  <div class="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center" :data-state="kind">
    <CrSpinner v-if="kind === 'loading'" class="size-6 text-accent-400" />
    <Inbox v-else-if="kind === 'empty'" class="size-8 text-ink-500" />
    <AlertTriangle v-else-if="kind === 'error'" class="size-8 text-sev-high" />
    <Lock v-else class="size-8 text-sev-critical" />
    <div class="text-sm font-semibold text-ink-100">
      {{ title || { loading: 'Memuat…', empty: 'Belum ada isi', error: 'Terjadi kesalahan', denied: 'Izin ditolak' }[kind] }}
    </div>
    <p v-if="message" class="max-w-md text-sm text-ink-400">{{ message }}</p>
    <p v-if="kind === 'denied' && missing.length" class="font-mono text-xs text-ink-400">memerlukan: {{ missing.join(', ') }}</p>
    <CrButton v-if="kind === 'error'" size="sm" @click="$emit('retry')"><RotateCw class="size-3.5" /> Coba lagi</CrButton>
    <slot />
  </div>
</template>
