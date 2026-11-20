<script setup>
import { X } from 'lucide-vue-next'
import { onBeforeUnmount, onMounted } from 'vue'
const props = defineProps({ title: String, open: Boolean, width: { type: String, default: 'max-w-lg' } })
const emit = defineEmits(['close'])
const onKey = (e) => { if (e.key === 'Escape' && props.open) emit('close') }
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
</script>
<template>
  <Teleport to="body">
    <div v-if="open" class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-ink-950/75 p-4 pt-[10vh] backdrop-blur-sm" @mousedown.self="emit('close')">
      <div role="dialog" aria-modal="true" :aria-label="title" :class="['panel w-full shadow-2xl', width]">
        <header class="panel-header">
          <h2 class="text-sm font-semibold text-ink-100">{{ title }}</h2>
          <button class="rounded p-1 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Tutup" @click="emit('close')"><X class="size-4" /></button>
        </header>
        <div class="p-4"><slot /></div>
        <footer v-if="$slots.footer" class="flex justify-end gap-2 border-t border-ink-700/60 px-4 py-3"><slot name="footer" /></footer>
      </div>
    </div>
  </Teleport>
</template>
