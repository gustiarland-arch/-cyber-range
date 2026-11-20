<script setup>
import { NodeResizer } from '@vue-flow/node-resizer'
import '@vue-flow/node-resizer/dist/style.css'
const props = defineProps({ id: String, data: Object, selected: Boolean })
const emit = defineEmits(['resize-end'])
</script>
<template>
  <div class="h-full w-full rounded-xl border-2 border-dashed" :style="{ borderColor: data.zone.color + 'aa', background: data.zone.color + '10' }">
    <NodeResizer v-if="data.editable" :is-visible="selected" :min-width="120" :min-height="90" :color="data.zone.color"
      @resize-end="(e) => data.onResize(props.id, e.params)" />
    <div class="flex items-center gap-2 px-3 py-1.5">
      <span class="rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider" :style="{ background: data.zone.color + '33', color: data.zone.color }">{{ data.zone.kind }}</span>
      <span class="text-xs font-semibold text-ink-200">{{ data.zone.name }}</span>
    </div>
  </div>
</template>
