<script setup>
import { computed } from 'vue'
import { ChevronLeft, ChevronRight } from 'lucide-vue-next'
const props = defineProps({ page: Number, pageSize: Number, total: Number })
const emit = defineEmits(['update:page'])
const pages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
</script>
<template>
  <div class="flex items-center justify-between gap-3 px-3 py-2 text-xs text-ink-400">
    <span>{{ total }} total · page {{ page }} / {{ pages }}</span>
    <div class="flex gap-1">
      <button class="rounded border border-ink-700 p-1 hover:bg-ink-800 disabled:opacity-40" :disabled="page <= 1" aria-label="Halaman sebelumnya" @click="emit('update:page', page - 1)"><ChevronLeft class="size-4" /></button>
      <button class="rounded border border-ink-700 p-1 hover:bg-ink-800 disabled:opacity-40" :disabled="page >= pages" aria-label="Halaman berikutnya" @click="emit('update:page', page + 1)"><ChevronRight class="size-4" /></button>
    </div>
  </div>
</template>
